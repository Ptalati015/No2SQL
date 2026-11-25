using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace No2SQL.Hosting.OAuth;

/// <summary>
/// Authorization codes (threat model R19): 32 random bytes, kept in memory only as SHA-256 hashes with the
/// client, redirect URI, PKCE challenge, scope and resource, valid for 60 seconds and usable once. A code
/// presented again revokes the family created from it.
/// </summary>
internal sealed class AuthorizationCodeStore(TimeProvider clock)
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromSeconds(60);

    // A redeemed code is remembered this long, so a late second use is still detected as reuse.
    private static readonly TimeSpan RememberFor = TimeSpan.FromMinutes(10);

    private const int MaxCodes = 10_000;

    private readonly Dictionary<string, CodeRecord> _codes = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    public string Issue(string clientId, string redirectUri, string codeChallenge, string scope, string resource)
    {
        var code = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        var now = clock.GetUtcNow();
        lock (_gate)
        {
            Prune(now);
            if (_codes.Count >= MaxCodes)
            {
                _codes.Remove(_codes.MinBy(c => c.Value.IssuedAt).Key);
            }

            _codes[GrantStore.Hash(code)] = new CodeRecord(clientId, redirectUri, codeChallenge, scope, resource, now);
        }

        return code;
    }

    /// <summary>
    /// Redeems a code. Any presentation of a known code uses it up, whether or not the rest matches, so a
    /// stolen code cannot be tried twice. The unknown-code and wrong-verifier paths do the same work.
    /// </summary>
    public CodeRedemption Redeem(string code, string clientId, string redirectUri, string codeVerifier)
    {
        var now = clock.GetUtcNow();
        var hash = GrantStore.Hash(code);
        var verifierHash = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier)));

        lock (_gate)
        {
            Prune(now);
            if (!_codes.TryGetValue(hash, out var record))
            {
                _ = FixedEquals(verifierHash, verifierHash);
                return CodeRedemption.Invalid;
            }

            if (record.Family is { } family)
            {
                return CodeRedemption.Reused(family);
            }

            record.Family = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(16));
            var matches = FixedEquals(verifierHash, record.CodeChallenge)
                & string.Equals(record.ClientId, clientId, StringComparison.Ordinal)
                & string.Equals(record.RedirectUri, redirectUri, StringComparison.Ordinal)
                & now - record.IssuedAt <= Lifetime;

            return matches ? CodeRedemption.Redeemed(record) : CodeRedemption.Invalid;
        }
    }

    private static bool FixedEquals(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(a), Encoding.ASCII.GetBytes(b));

    private void Prune(DateTimeOffset now)
    {
        foreach (var stale in _codes.Where(c => now - c.Value.IssuedAt > RememberFor).Select(c => c.Key).ToList())
        {
            _codes.Remove(stale);
        }
    }
}

/// <summary>What a code was issued for. <see cref="Family"/> is set when the code is first presented.</summary>
internal sealed class CodeRecord(string clientId, string redirectUri, string codeChallenge, string scope, string resource, DateTimeOffset issuedAt)
{
    public string ClientId { get; } = clientId;
    public string RedirectUri { get; } = redirectUri;
    public string CodeChallenge { get; } = codeChallenge;
    public string Scope { get; } = scope;
    public string Resource { get; } = resource;
    public DateTimeOffset IssuedAt { get; } = issuedAt;
    public string? Family { get; set; }
}

internal sealed record CodeRedemption(bool Ok, CodeRecord? Record, string? ReusedFamily)
{
    public static readonly CodeRedemption Invalid = new(false, null, null);

    public static CodeRedemption Reused(string family) => new(false, null, family);

    public static CodeRedemption Redeemed(CodeRecord record) => new(true, record, null);
}

/// <summary>An authorization request that passed validation and waits for the owner's login and consent.</summary>
internal sealed class PendingAuthorization
{
    public required string Id { get; init; }
    public required ResolvedClient Client { get; init; }
    public required string RedirectUri { get; init; }
    public required string CodeChallenge { get; init; }
    public required string Scope { get; init; }
    public required string Resource { get; init; }
    public string? State { get; init; }
    public required string LoginToken { get; init; }
    public required string ConsentToken { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }

    /// <summary>The owner session this request was bound to at login (or when it arrived with one).</summary>
    public string? SessionId { get; set; }
}

/// <summary>
/// Owner sessions (R16) and pending authorization requests, in memory with a 10-minute lifetime. Session ids
/// and the anti-forgery tokens are 32 random bytes.
/// </summary>
internal sealed class InteractionStore(TimeProvider clock)
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(10);
    private const int MaxEntries = 1000;

    private readonly Dictionary<string, PendingAuthorization> _requests = new(StringComparer.Ordinal);
    private readonly Dictionary<string, DateTimeOffset> _sessions = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    public static string NewSecret() => Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));

    public PendingAuthorization Add(ResolvedClient client, string redirectUri, string codeChallenge, string scope, string resource, string? state, string? sessionId)
    {
        var request = new PendingAuthorization
        {
            Id = NewSecret(),
            Client = client,
            RedirectUri = redirectUri,
            CodeChallenge = codeChallenge,
            Scope = scope,
            Resource = resource,
            State = state,
            LoginToken = NewSecret(),
            ConsentToken = NewSecret(),
            ExpiresAt = clock.GetUtcNow() + Lifetime,
            SessionId = sessionId,
        };

        lock (_gate)
        {
            Prune();
            if (_requests.Count >= MaxEntries)
            {
                _requests.Remove(_requests.MinBy(r => r.Value.ExpiresAt).Key);
            }

            _requests[request.Id] = request;
        }

        return request;
    }

    public PendingAuthorization? Find(string? id)
    {
        if (string.IsNullOrEmpty(id))
        {
            return null;
        }

        lock (_gate)
        {
            Prune();
            return _requests.GetValueOrDefault(id);
        }
    }

    /// <summary>Removes a request so it cannot be answered twice. Returns false when it was already gone.</summary>
    public bool Remove(string id)
    {
        lock (_gate)
        {
            return _requests.Remove(id);
        }
    }

    /// <summary>A new owner session (a new id at every login, never one the browser offered).</summary>
    public string StartSession()
    {
        var id = NewSecret();
        lock (_gate)
        {
            Prune();
            if (_sessions.Count >= MaxEntries)
            {
                _sessions.Remove(_sessions.MinBy(s => s.Value).Key);
            }

            _sessions[id] = clock.GetUtcNow() + Lifetime;
        }

        return id;
    }

    public bool IsSession(string? id)
    {
        if (string.IsNullOrEmpty(id))
        {
            return false;
        }

        lock (_gate)
        {
            Prune();
            return _sessions.ContainsKey(id);
        }
    }

    private void Prune()
    {
        var now = clock.GetUtcNow();
        foreach (var stale in _requests.Where(r => r.Value.ExpiresAt <= now).Select(r => r.Key).ToList())
        {
            _requests.Remove(stale);
        }

        foreach (var stale in _sessions.Where(s => s.Value <= now).Select(s => s.Key).ToList())
        {
            _sessions.Remove(stale);
        }
    }
}

/// <summary>
/// Owner password guessing limits (R14): after 5 failures from one address each attempt waits 2 s, doubling
/// up to 60 s; after 20 failures in an hour that address is refused without checking; after 100 failures in
/// an hour from all addresses together, login is refused for everyone until the hour has passed.
/// An attempt is counted when it starts, before the password is checked, so attempts sent at the same time
/// are not all judged against the same count; a correct password takes its own attempt back.
/// </summary>
internal sealed class LoginThrottle(TimeProvider clock)
{
    public const int FreeFailures = 5;
    public const int MaxFailuresPerAddress = 20;
    public const int MaxFailuresGlobal = 100;
    public static readonly TimeSpan Window = TimeSpan.FromHours(1);
    public static readonly TimeSpan FirstDelay = TimeSpan.FromSeconds(2);
    public static readonly TimeSpan MaxDelay = TimeSpan.FromSeconds(60);

    private const int MaxAddresses = 10_000;

    private readonly Dictionary<string, Queue<DateTimeOffset>> _byAddress = new(StringComparer.Ordinal);
    private readonly List<DateTimeOffset> _global = [];
    private readonly object _gate = new();

    /// <summary>
    /// Starts an attempt from this address: whether it is refused outright, how long to wait before checking
    /// the password, and the attempt's own mark for <see cref="Succeeded"/>. An attempt that is not refused
    /// counts as a failure from this moment.
    /// </summary>
    public (bool Refused, TimeSpan Delay, DateTimeOffset Attempt) Begin(string address)
    {
        lock (_gate)
        {
            var now = clock.GetUtcNow();
            _global.RemoveAll(t => now - t >= Window);
            if (!_byAddress.TryGetValue(address, out var queue))
            {
                if (_byAddress.Count >= MaxAddresses)
                {
                    foreach (var stale in _byAddress.Where(a => Trim(a.Value, now) == 0).Select(a => a.Key).ToList())
                    {
                        _byAddress.Remove(stale);
                    }
                }

                _byAddress[address] = queue = new Queue<DateTimeOffset>();
            }

            var failures = Trim(queue, now);
            if (_global.Count >= MaxFailuresGlobal || failures >= MaxFailuresPerAddress)
            {
                return (true, TimeSpan.Zero, now);
            }

            var delay = TimeSpan.Zero;
            if (failures >= FreeFailures)
            {
                delay = FirstDelay * Math.Pow(2, failures - FreeFailures);
                delay = delay > MaxDelay ? MaxDelay : delay;
            }

            queue.Enqueue(now);
            _global.Add(now);
            return (false, delay, now);
        }
    }

    /// <summary>The password was right: forgets this address's failures and takes the attempt out of the total.</summary>
    public void Succeeded(string address, DateTimeOffset attempt)
    {
        lock (_gate)
        {
            _byAddress.Remove(address);
            _global.Remove(attempt);
        }
    }

    private static int Trim(Queue<DateTimeOffset> queue, DateTimeOffset now)
    {
        while (queue.Count > 0 && now - queue.Peek() >= Window)
        {
            queue.Dequeue();
        }

        return queue.Count;
    }
}

/// <summary>A sliding-window limit per key (client address), on the injected clock (R4, R20, R31).</summary>
internal sealed class SlidingWindowLimiter(int limit, TimeSpan window, TimeProvider clock)
{
    private const int MaxKeys = 10_000;

    private readonly Dictionary<string, Queue<DateTimeOffset>> _hits = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    /// <summary>Counts one request. Returns false, with the time until a slot frees up, when the limit is reached.</summary>
    public bool TryAcquire(string key, out TimeSpan retryAfter)
    {
        lock (_gate)
        {
            var now = clock.GetUtcNow();
            if (!_hits.TryGetValue(key, out var queue))
            {
                if (_hits.Count >= MaxKeys)
                {
                    foreach (var stale in _hits.Where(h => h.Value.Count == 0 || now - h.Value.Last() >= window).Select(h => h.Key).ToList())
                    {
                        _hits.Remove(stale);
                    }
                }

                _hits[key] = queue = new Queue<DateTimeOffset>();
            }

            while (queue.Count > 0 && now - queue.Peek() >= window)
            {
                queue.Dequeue();
            }

            if (queue.Count >= limit)
            {
                retryAfter = window - (now - queue.Peek());
                return false;
            }

            queue.Enqueue(now);
            retryAfter = TimeSpan.Zero;
            return true;
        }
    }
}
