using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace No2SQL.Hosting.OAuth;

/// <summary>
/// The owner's password (threat model R14, R15). Only its SHA-256 is held, and attempts are compared by
/// hash with <see cref="CryptographicOperations.FixedTimeEquals"/>, so the time taken does not depend on
/// the attempt.
/// </summary>
internal sealed class OwnerCredential
{
    public const int MinimumLength = 12;
    public const int GeneratedLength = 24;
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    private readonly byte[] _hash;

    private OwnerCredential(byte[] hash) => _hash = hash;

    public static OwnerCredential FromPassword(string password) => new(SHA256.HashData(Encoding.UTF8.GetBytes(password)));

    public bool Verify(string? attempt) =>
        CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(attempt ?? "")), _hash);

    /// <summary>
    /// The configured <c>NO2SQL_OWNER_PASSWORD</c>, or the generated password whose hash is stored in the data
    /// directory, or a newly generated one (24 characters from a 62-symbol alphabet, about 143 bits). Only a
    /// newly generated password is returned in <c>Generated</c>, for the caller to print once.
    /// </summary>
    /// <exception cref="OAuthDataException">The stored hash cannot be read, or the data directory cannot be written.</exception>
    public static (OwnerCredential Credential, string? Generated) Resolve(string? configuredPassword, OAuthDataDirectory directory, TimeProvider clock)
    {
        if (configuredPassword is not null)
        {
            return (FromPassword(configuredPassword), null);
        }

        return directory.WithLock(() =>
        {
            var path = directory.File(OAuthDataDirectory.OwnerPasswordFile);
            var stored = directory.Read<OwnerPasswordDocument>(OAuthDataDirectory.OwnerPasswordFile);
            if (stored is not null)
            {
                byte[] hash;
                try
                {
                    hash = Base64UrlEncoder.DecodeBytes(stored.Sha256);
                }
                catch (FormatException)
                {
                    throw new OAuthDataException($"{path} is damaged. Delete it to generate a new owner password at the next start, or set NO2SQL_OWNER_PASSWORD.");
                }

                if (hash.Length != 32)
                {
                    throw new OAuthDataException($"{path} is damaged. Delete it to generate a new owner password at the next start, or set NO2SQL_OWNER_PASSWORD.");
                }

                return (new OwnerCredential(hash), (string?)null);
            }

            var generated = RandomNumberGenerator.GetString(Alphabet, GeneratedLength);
            var credential = FromPassword(generated);
            directory.Write(OAuthDataDirectory.OwnerPasswordFile, new OwnerPasswordDocument
            {
                Sha256 = Base64UrlEncoder.Encode(credential._hash),
                CreatedAt = clock.GetUtcNow(),
            });
            return (credential, generated);
        });
    }

    /// <summary>The notice that shows a generated password, the only place it is ever written.</summary>
    public static string GeneratedNotice(string password, OAuthDataDirectory directory) => string.Join(Environment.NewLine,
        "[No2SQL] ======================================================================",
        "[No2SQL] Owner password for the built-in sign-in, shown only this once:",
        $"[No2SQL]     {password}",
        "[No2SQL] Keep it in a password manager. You type it when an AI client connects.",
        $"[No2SQL] Only its SHA-256 is kept, in {directory.File(OAuthDataDirectory.OwnerPasswordFile)}.",
        "[No2SQL] Container logs keep this notice; set NO2SQL_OWNER_PASSWORD instead if that matters.",
        "[No2SQL] For a new password, set NO2SQL_OWNER_PASSWORD, or delete that file and restart.",
        "[No2SQL] ======================================================================");

    public override string ToString() => nameof(OwnerCredential);
}

/// <summary>The JSON of <c>owner-password.json</c>: the SHA-256 of a generated password, never the password.</summary>
internal sealed class OwnerPasswordDocument
{
    [JsonPropertyName("sha256")] public string Sha256 { get; set; } = "";
    [JsonPropertyName("created_at")] public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>
/// Access tokens (R22): ES256 JWTs with <c>kid</c>, <c>typ: at+jwt</c>, and the claims <c>iss</c>, <c>sub</c>
/// (always "owner"), <c>aud</c> (the MCP URL, one string), <c>client_id</c>, <c>scope</c>, <c>jti</c>,
/// <c>iat</c> and <c>exp</c>.
/// </summary>
internal sealed class AccessTokenIssuer(SigningKeyStore keys, TimeProvider clock, HttpAuthOptions auth)
{
    public const string Subject = "owner";

    private readonly JsonWebTokenHandler _handler = new() { SetDefaultTimesOnTokenCreation = false };

    public TimeSpan Lifetime => auth.AccessTokenLifetime;

    /// <summary>A new jti and the expiry of a token issued now, so the grant can record them before the token exists.</summary>
    public (string Jti, DateTimeOffset IssuedAt, DateTimeOffset Expires) Next()
    {
        var now = clock.GetUtcNow();
        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(now.ToUnixTimeSeconds());
        return (Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(16)), issuedAt, issuedAt + Lifetime);
    }

    public string Create(string jti, DateTimeOffset issuedAt, DateTimeOffset expires, string clientId, string scope) =>
        _handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = auth.Issuer,
            Audience = auth.McpUrl,
            IssuedAt = issuedAt.UtcDateTime,
            Expires = expires.UtcDateTime,
            TokenType = "at+jwt",
            Claims = new Dictionary<string, object>
            {
                ["sub"] = Subject,
                ["client_id"] = clientId,
                ["scope"] = scope,
                ["jti"] = jti,
            },
            SigningCredentials = new SigningCredentials(keys.SigningKey, SecurityAlgorithms.EcdsaSha256),
        });
}
