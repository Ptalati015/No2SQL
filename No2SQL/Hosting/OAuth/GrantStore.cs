using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using Microsoft.IdentityModel.Tokens;

namespace No2SQL.Hosting.OAuth;

/// <summary>
/// <c>refresh-tokens.json</c>: one grant per approved authorization (a refresh-token family), and the
/// access tokens that must be refused before their expiry (threat model R19, R21, R23).
/// <list type="bullet">
/// <item>Refresh tokens are 32 random bytes; only their SHA-256 is stored. Every refresh rotates the token,
/// and presenting a used one revokes the whole family. A family lives at most 30 days.</item>
/// <item>The access tokens issued in a family are remembered until they expire, so revoking the family
/// (a reused code or refresh token, or <c>No2SQL oauth revoke &lt;client_id&gt;</c>) also refuses them.</item>
/// </list>
/// </summary>
internal sealed class GrantStore
{
    public static readonly TimeSpan RefreshTokenLifetime = TimeSpan.FromDays(30);

    // Used refresh-token hashes kept per family for reuse detection. Hourly refreshes for 30 days stay under it.
    private const int MaxUsedHashes = 1000;

    private readonly SharedDocument<GrantsDocument> _document;
    private readonly TimeProvider _clock;

    // Families revoked while their grant was still being created (a code reused during its own exchange).
    private readonly ConcurrentDictionary<string, DateTimeOffset> _revokedFamilies = new(StringComparer.Ordinal);

    public GrantStore(OAuthDataDirectory directory, TimeProvider clock)
    {
        _clock = clock;
        _document = new SharedDocument<GrantsDocument>(directory, OAuthDataDirectory.GrantsFile, clock, d => d.BuildIndex());
    }

    /// <summary>Creates a family for a redeemed code and returns its first refresh token, or null when the family was already revoked.</summary>
    public string? CreateGrant(string family, string clientId, string scope, string accessTokenId, DateTimeOffset accessTokenExpires)
    {
        var refreshToken = NewToken();
        var created = _document.Update(document =>
        {
            var now = _clock.GetUtcNow();
            document.Prune(now);
            if (_revokedFamilies.ContainsKey(family))
            {
                return false;
            }

            document.Grants.Add(new Grant
            {
                Family = family,
                ClientId = clientId,
                Scope = scope,
                CreatedAt = now,
                ExpiresAt = now + RefreshTokenLifetime,
                RefreshHash = Hash(refreshToken),
                AccessTokens = [new IssuedAccessToken { Jti = accessTokenId, Expires = accessTokenExpires }],
            });
            return true;
        }, created => created);

        return created ? refreshToken : null;
    }

    /// <summary>
    /// Rotates a refresh token. A used token revokes its family; an unknown, expired or other client's token is
    /// refused; a requested scope outside the grant's is refused before anything is rotated.
    /// </summary>
    public RefreshResult Refresh(string refreshToken, string clientId, IReadOnlyCollection<string>? requestedScopes, string accessTokenId, DateTimeOffset accessTokenExpires)
    {
        var presented = Hash(refreshToken);
        var next = NewToken();
        return _document.Update(document =>
        {
            var now = _clock.GetUtcNow();
            document.Prune(now);

            var current = document.Grants.FirstOrDefault(g => g.RefreshHash == presented);
            if (current is null)
            {
                var reused = document.Grants.FirstOrDefault(g => g.UsedHashes.Contains(presented));
                if (reused is null)
                {
                    return RefreshResult.Invalid;
                }

                RevokeFamily(document, reused, now);
                return RefreshResult.Reused(reused.Family, reused.ClientId);
            }

            if (!string.Equals(current.ClientId, clientId, StringComparison.Ordinal))
            {
                return RefreshResult.Invalid;
            }

            var granted = current.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (requestedScopes is { Count: > 0 } && !requestedScopes.All(granted.Contains))
            {
                return RefreshResult.ScopeRefused;
            }

            current.UsedHashes.Add(presented);
            if (current.UsedHashes.Count > MaxUsedHashes)
            {
                current.UsedHashes.RemoveRange(0, current.UsedHashes.Count - MaxUsedHashes);
            }

            current.RefreshHash = Hash(next);
            current.AccessTokens.Add(new IssuedAccessToken { Jti = accessTokenId, Expires = accessTokenExpires });
            var scope = requestedScopes is { Count: > 0 } ? string.Join(' ', requestedScopes) : current.Scope;
            return RefreshResult.Rotated(next, scope, current.Family);
        }, result => result.Outcome is RefreshOutcome.Rotated or RefreshOutcome.Reused);
    }

    /// <summary>Revokes one family (a reused authorization code): deletes its refresh token and refuses its access tokens.</summary>
    public void RevokeFamily(string family)
    {
        var now = _clock.GetUtcNow();
        _revokedFamilies[family] = now;
        foreach (var stale in _revokedFamilies.Where(f => now - f.Value > TimeSpan.FromMinutes(10)).Select(f => f.Key).ToList())
        {
            _revokedFamilies.TryRemove(stale, out _);
        }

        _document.Update(document =>
        {
            var grant = document.Grants.FirstOrDefault(g => g.Family == family);
            if (grant is not null)
            {
                RevokeFamily(document, grant, now);
            }

            return grant is not null;
        }, revoked => revoked);
    }

    /// <summary>True when an access token was revoked before its expiry. Sees command-line revocations within a second.</summary>
    public bool IsAccessTokenRevoked(string jti) => _document.Read().RevokedIndex.Contains(jti);

    /// <summary><c>revoke &lt;client_id&gt;</c>: deletes every family of the client and refuses its live access tokens. Returns the number of families.</summary>
    public static int RevokeClient(OAuthDataDirectory directory, string clientId, DateTimeOffset now) => directory.WithLock(() =>
    {
        var document = directory.Read<GrantsDocument>(OAuthDataDirectory.GrantsFile) ?? new GrantsDocument();
        document.Prune(now);
        var families = document.Grants.Where(g => g.ClientId == clientId).ToList();
        foreach (var grant in families)
        {
            RevokeFamily(document, grant, now);
        }

        directory.Write(OAuthDataDirectory.GrantsFile, document);
        return families.Count;
    });

    /// <summary><c>revoke-all</c>: deletes every family. (The key replacement is what refuses the access tokens.) Returns the number of families.</summary>
    public static int RevokeAll(OAuthDataDirectory directory) => directory.WithLock(() =>
    {
        int count;
        try
        {
            count = directory.Read<GrantsDocument>(OAuthDataDirectory.GrantsFile)?.Grants.Count ?? 0;
        }
        catch (OAuthDataException)
        {
            count = 0;   // an unreadable file is replaced as well
        }

        directory.Write(OAuthDataDirectory.GrantsFile, new GrantsDocument());
        return count;
    });

    /// <summary>For <c>No2SQL oauth list</c>: the number of live families per client.</summary>
    public static IReadOnlyDictionary<string, int> CountByClient(OAuthDataDirectory directory, DateTimeOffset now) =>
        (directory.Read<GrantsDocument>(OAuthDataDirectory.GrantsFile) ?? new GrantsDocument()).Grants
            .Where(g => g.ExpiresAt > now)
            .GroupBy(g => g.ClientId)
            .ToDictionary(g => g.Key, g => g.Count(), StringComparer.Ordinal);

    /// <summary>SHA-256 of a token, base64url. Only this form of a refresh token is ever stored.</summary>
    public static string Hash(string token) => Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    /// <summary>32 random bytes, base64url.</summary>
    public static string NewToken() => Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));

    private static void RevokeFamily(GrantsDocument document, Grant grant, DateTimeOffset now)
    {
        foreach (var token in grant.AccessTokens.Where(t => t.Expires + HttpAuth.ClockSkew > now))
        {
            document.Revoked.Add(new IssuedAccessToken { Jti = token.Jti, Expires = token.Expires });
        }

        document.Grants.Remove(grant);
    }
}

internal enum RefreshOutcome
{
    Invalid,
    ScopeRefused,
    Reused,
    Rotated,
}

/// <summary>What a refresh attempt did. <see cref="RefreshToken"/> is set only when the token was rotated.</summary>
internal sealed record RefreshResult(RefreshOutcome Outcome, string? RefreshToken, string? Scope, string? Family, string? ClientId)
{
    public static readonly RefreshResult Invalid = new(RefreshOutcome.Invalid, null, null, null, null);

    public static readonly RefreshResult ScopeRefused = new(RefreshOutcome.ScopeRefused, null, null, null, null);

    public static RefreshResult Reused(string family, string clientId) => new(RefreshOutcome.Reused, null, null, family, clientId);

    public static RefreshResult Rotated(string refreshToken, string scope, string family) => new(RefreshOutcome.Rotated, refreshToken, scope, family, null);

    // Never print the token.
    private bool PrintMembers(StringBuilder builder)
    {
        builder.Append("Outcome = ").Append(Outcome).Append(", Family = ").Append(Family);
        return true;
    }
}

/// <summary>The JSON of <c>refresh-tokens.json</c>.</summary>
internal sealed class GrantsDocument
{
    [JsonPropertyName("grants")]
    public List<Grant> Grants { get; set => field = value ?? []; } = [];

    [JsonPropertyName("revoked_access_tokens")]
    public List<IssuedAccessToken> Revoked { get; set => field = value ?? []; } = [];

    [JsonIgnore]
    public HashSet<string> RevokedIndex { get; private set; } = new(StringComparer.Ordinal);

    public void BuildIndex() => RevokedIndex = new HashSet<string>(Revoked.Select(r => r.Jti), StringComparer.Ordinal);

    // Drops expired families, expired access-token records and revocations that no longer matter.
    public void Prune(DateTimeOffset now)
    {
        Grants.RemoveAll(g => g.ExpiresAt <= now);
        foreach (var grant in Grants)
        {
            grant.AccessTokens.RemoveAll(t => t.Expires + HttpAuth.ClockSkew <= now);
        }

        Revoked.RemoveAll(t => t.Expires + HttpAuth.ClockSkew <= now);
    }
}

/// <summary>One refresh-token family.</summary>
internal sealed class Grant
{
    [JsonPropertyName("family")] public string Family { get; set; } = "";
    [JsonPropertyName("client_id")] public string ClientId { get; set; } = "";
    [JsonPropertyName("scope")] public string Scope { get; set; } = "";
    [JsonPropertyName("created_at")] public DateTimeOffset CreatedAt { get; set; }
    [JsonPropertyName("expires_at")] public DateTimeOffset ExpiresAt { get; set; }
    [JsonPropertyName("refresh_hash")] public string RefreshHash { get; set; } = "";
    [JsonPropertyName("used_hashes")] public List<string> UsedHashes { get; set => field = value ?? []; } = [];
    [JsonPropertyName("access_tokens")] public List<IssuedAccessToken> AccessTokens { get; set => field = value ?? []; } = [];
}

/// <summary>An access token by its jti and expiry. The token itself is never stored.</summary>
internal sealed class IssuedAccessToken
{
    [JsonPropertyName("jti")] public string Jti { get; set; } = "";
    [JsonPropertyName("exp")] public DateTimeOffset Expires { get; set; }
}
