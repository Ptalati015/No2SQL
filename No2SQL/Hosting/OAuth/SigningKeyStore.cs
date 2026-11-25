using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace No2SQL.Hosting.OAuth;

/// <summary>
/// The ES256 signing keys in <c>signing-keys.json</c>, a JWK Set whose entries carry the private key
/// (threat model R22, R23, R26, R27). One key is <c>active</c> and signs new access tokens; after
/// <c>rotate-keys</c> the previous one is <c>retiring</c> and still validates until its <c>retire_at</c>.
/// The running server re-reads the file at most once per second when it changes, so <c>revoke-all</c>
/// and <c>rotate-keys</c> take effect without a restart.
/// </summary>
internal sealed class SigningKeyStore
{
    private static readonly TimeSpan CheckInterval = TimeSpan.FromSeconds(1);

    private readonly OAuthDataDirectory _directory;
    private readonly TimeProvider _clock;
    private readonly ILogger _log;
    private readonly object _gate = new();

    private LoadedKeys _keys;
    private (DateTime, long)? _stamp;
    private long _lastCheck;

    public SigningKeyStore(OAuthDataDirectory directory, TimeProvider clock, ILogger<SigningKeyStore> log)
    {
        _directory = directory;
        _clock = clock;
        _log = log;
        _keys = LoadedKeys.Empty;
        _lastCheck = clock.GetTimestamp();
        Reload(throwOnError: true);
    }

    /// <summary>
    /// Reads the key file, creating it with one new active key when there is none. Called once at start-up,
    /// so a damaged key file stops the server instead of being replaced silently.
    /// </summary>
    /// <exception cref="OAuthDataException">The key file exists but cannot be used.</exception>
    public static void EnsureCreated(OAuthDataDirectory directory)
    {
        directory.WithLock(() =>
        {
            var document = directory.Read<KeySetDocument>(OAuthDataDirectory.KeysFile);
            if (document is null)
            {
                directory.Write(OAuthDataDirectory.KeysFile, new KeySetDocument { Keys = [StoredKey.Generate()] });
                return;
            }

            _ = LoadedKeys.From(document, DateTimeOffset.MinValue, directory.File(OAuthDataDirectory.KeysFile));
        });
    }

    /// <summary>The key that signs new access tokens.</summary>
    /// <exception cref="OAuthDataException">There is no usable active key (the file changed and could not be read).</exception>
    public ECDsaSecurityKey SigningKey
    {
        get
        {
            CheckForChanges();
            return Volatile.Read(ref _keys).Signing ?? throw new OAuthDataException($"{_directory.File(OAuthDataDirectory.KeysFile)} has no usable active key.");
        }
    }

    /// <summary>The public keys that validate tokens now: the active key and retiring keys before their retire_at.</summary>
    public IEnumerable<SecurityKey> ValidationKeys(string? kid)
    {
        CheckForChanges();
        var now = _clock.GetUtcNow();
        return Volatile.Read(ref _keys).Public
            .Where(k => k.RetireAt is null || k.RetireAt > now)
            .Where(k => kid is null || string.Equals(k.Key.KeyId, kid, StringComparison.Ordinal))
            .Select(k => (SecurityKey)k.Key)
            .ToList();
    }

    /// <summary>The JWKS document: public parameters only (kty, crv, x, y, kid, use, alg), never d.</summary>
    public string JwksJson()
    {
        CheckForChanges();
        var now = _clock.GetUtcNow();
        var keys = Volatile.Read(ref _keys).Public
            .Where(k => k.RetireAt is null || k.RetireAt > now)
            .Select(k => new Dictionary<string, string>
            {
                ["kty"] = "EC",
                ["crv"] = "P-256",
                ["x"] = k.X,
                ["y"] = k.Y,
                ["kid"] = k.Key.KeyId,
                ["use"] = "sig",
                ["alg"] = "ES256",
            });
        return JsonSerializer.Serialize(new { keys });
    }

    // At most once per second: compare the file's stamp and reload it when another process changed it.
    private void CheckForChanges()
    {
        var now = _clock.GetTimestamp();
        if (_clock.GetElapsedTime(Volatile.Read(ref _lastCheck), now) < CheckInterval)
        {
            return;
        }

        lock (_gate)
        {
            if (_clock.GetElapsedTime(_lastCheck, now) < CheckInterval)
            {
                return;
            }

            _lastCheck = now;
            if (_directory.Stamp(OAuthDataDirectory.KeysFile) != _stamp)
            {
                Reload(throwOnError: false);
            }
        }
    }

    private void Reload(bool throwOnError)
    {
        var path = _directory.File(OAuthDataDirectory.KeysFile);
        try
        {
            var stamp = _directory.Stamp(OAuthDataDirectory.KeysFile);
            var document = _directory.Read<KeySetDocument>(OAuthDataDirectory.KeysFile)
                ?? throw new OAuthDataException($"{path} does not exist.");
            Volatile.Write(ref _keys, LoadedKeys.From(document, DateTimeOffset.MinValue, path));
            _stamp = stamp;
        }
        catch (OAuthDataException ex) when (!throwOnError)
        {
            // Fail closed: with no keys every access token is rejected until the file is readable again.
            Volatile.Write(ref _keys, LoadedKeys.Empty);
            _stamp = null;
            _log.LogError("The signing keys could not be reloaded, so every access token is refused: {Reason}", ex.Message);
        }
    }

    /// <summary><c>rotate-keys</c>: a new active key; the old active key retires after <paramref name="grace"/>; retired keys are dropped.</summary>
    public static (string NewKid, string? RetiringKid, DateTimeOffset RetireAt) Rotate(OAuthDataDirectory directory, DateTimeOffset now, TimeSpan grace) =>
        directory.WithLock(() =>
        {
            var path = directory.File(OAuthDataDirectory.KeysFile);
            var document = directory.Read<KeySetDocument>(OAuthDataDirectory.KeysFile)
                ?? throw new OAuthDataException($"{path} does not exist. Start the server once with NO2SQL_OAUTH_BUILTIN=true first.");
            _ = LoadedKeys.From(document, now, path);

            var retireAt = now + grace;
            string? retiringKid = null;
            var kept = new List<StoredKey>();
            foreach (var key in document.Keys)
            {
                if (key.Status == StoredKey.Active)
                {
                    key.Status = StoredKey.Retiring;
                    key.RetireAt = retireAt;
                    retiringKid = key.Kid;
                    kept.Add(key);
                }
                else if (key.RetireAt is { } at && at > now)
                {
                    kept.Add(key);
                }
            }

            var fresh = StoredKey.Generate();
            kept.Insert(0, fresh);
            directory.Write(OAuthDataDirectory.KeysFile, new KeySetDocument { Keys = kept });
            return (fresh.Kid, retiringKid, retireAt);
        });

    /// <summary><c>revoke-all</c>: one new active key and nothing else, so every token signed before fails kid lookup.</summary>
    public static string ReplaceAll(OAuthDataDirectory directory) => directory.WithLock(() =>
    {
        var fresh = StoredKey.Generate();
        directory.Write(OAuthDataDirectory.KeysFile, new KeySetDocument { Keys = [fresh] });
        return fresh.Kid;
    });

    /// <summary>For <c>No2SQL oauth list</c>: kid, status and retire time of each key. Never key material.</summary>
    public static IReadOnlyList<(string Kid, string Status, DateTimeOffset? RetireAt)> Describe(OAuthDataDirectory directory)
    {
        var document = directory.Read<KeySetDocument>(OAuthDataDirectory.KeysFile);
        return document?.Keys is null ? [] : document.Keys.Select(k => (k.Kid, k.Status ?? "no status", k.RetireAt)).ToList();
    }

    private sealed record PublicKey(ECDsaSecurityKey Key, string X, string Y, DateTimeOffset? RetireAt);

    private sealed record LoadedKeys(ECDsaSecurityKey? Signing, IReadOnlyList<PublicKey> Public)
    {
        public static readonly LoadedKeys Empty = new(null, []);

        // Every entry must be a complete P-256 private key with a status; exactly one is active.
        public static LoadedKeys From(KeySetDocument document, DateTimeOffset now, string path)
        {
            var refusal = $"{path} cannot be used as the signing key set. Fix it from a backup, or run 'No2SQL oauth revoke-all' to replace it (every client then has to sign in again).";
            if (document.Keys is null || document.Keys.Count(k => k.Status == StoredKey.Active) != 1)
            {
                throw new OAuthDataException(refusal);
            }

            ECDsaSecurityKey? signing = null;
            var publicKeys = new List<PublicKey>();
            foreach (var stored in document.Keys)
            {
                if (stored.Kty != "EC" || stored.Crv != "P-256" || stored.Alg != "ES256" || stored.Use != "sig"
                    || string.IsNullOrEmpty(stored.Kid)
                    || (stored.Status != StoredKey.Active && stored.Status != StoredKey.Retiring)
                    || (stored.Status == StoredKey.Retiring && stored.RetireAt is null))
                {
                    throw new OAuthDataException(refusal);
                }

                ECParameters parameters;
                try
                {
                    parameters = new ECParameters
                    {
                        Curve = ECCurve.NamedCurves.nistP256,
                        Q = new ECPoint { X = Base64UrlEncoder.DecodeBytes(stored.X), Y = Base64UrlEncoder.DecodeBytes(stored.Y) },
                        D = Base64UrlEncoder.DecodeBytes(stored.D),
                    };
                    parameters.Validate();
                }
                catch (Exception ex) when (ex is FormatException or ArgumentException or CryptographicException)
                {
                    throw new OAuthDataException(refusal);
                }

                if (stored.RetireAt is { } retireAt && retireAt <= now)
                {
                    continue;
                }

                try
                {
                    if (stored.Status == StoredKey.Active)
                    {
                        signing = new ECDsaSecurityKey(ECDsa.Create(parameters)) { KeyId = stored.Kid };
                    }

                    var publicOnly = ECDsa.Create(new ECParameters { Curve = parameters.Curve, Q = parameters.Q });
                    publicKeys.Add(new PublicKey(new ECDsaSecurityKey(publicOnly) { KeyId = stored.Kid }, stored.X!, stored.Y!, stored.RetireAt));
                }
                catch (CryptographicException)
                {
                    throw new OAuthDataException(refusal);
                }
            }

            return new LoadedKeys(signing, publicKeys);
        }
    }
}

/// <summary>The JSON of <c>signing-keys.json</c> (RFC 7517 JWK Set).</summary>
internal sealed class KeySetDocument
{
    [JsonPropertyName("keys")]
    public List<StoredKey> Keys { get; set; } = [];
}

/// <summary>One private EC key as stored: a JWK plus <c>status</c> and, for a retiring key, <c>retire_at</c>.</summary>
internal sealed class StoredKey
{
    public const string Active = "active";
    public const string Retiring = "retiring";

    [JsonPropertyName("kty")] public string? Kty { get; set; }
    [JsonPropertyName("crv")] public string? Crv { get; set; }
    [JsonPropertyName("x")] public string? X { get; set; }
    [JsonPropertyName("y")] public string? Y { get; set; }
    [JsonPropertyName("d")] public string? D { get; set; }
    [JsonPropertyName("kid")] public string Kid { get; set; } = "";
    [JsonPropertyName("alg")] public string? Alg { get; set; }
    [JsonPropertyName("use")] public string? Use { get; set; }
    [JsonPropertyName("status")] public string? Status { get; set; }

    [JsonPropertyName("retire_at")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DateTimeOffset? RetireAt { get; set; }

    /// <summary>A new P-256 key. Its kid is the RFC 7638 thumbprint of the public key.</summary>
    public static StoredKey Generate()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var p = ecdsa.ExportParameters(includePrivateParameters: true);
        var x = Base64UrlEncoder.Encode(p.Q.X);
        var y = Base64UrlEncoder.Encode(p.Q.Y);
        var thumbprintInput = $"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}";
        var kid = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(thumbprintInput)));
        var key = new StoredKey { Kty = "EC", Crv = "P-256", X = x, Y = y, D = Base64UrlEncoder.Encode(p.D), Kid = kid, Alg = "ES256", Use = "sig", Status = Active };
        CryptographicOperations.ZeroMemory(p.D);
        return key;
    }
}
