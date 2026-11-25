using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using No2SQL.Hosting;

namespace No2SQL.Tests.Infrastructure;

/// <summary>
/// A stand-in identity provider for tests: signing keys in memory, handed to No2SQL's JWT scheme as
/// its configuration, so no metadata or JWKS is fetched. Only the test host can do this.
/// </summary>
internal sealed class TestIdentityProvider
{
    public const string Authority = "https://login.example.test/";
    public const string PublicUrl = "https://mcp.example.test";
    public const string McpUrl = PublicUrl + "/mcp";

    public ECDsaSecurityKey EcKey { get; } = new(ECDsa.Create(ECCurve.NamedCurves.nistP256)) { KeyId = "ec-1" };

    public RsaSecurityKey RsaKey { get; } = new(RSA.Create(2048)) { KeyId = "rsa-1" };

    /// <summary>Keys the server trusts. Tests may add more (for example a symmetric key, to show it is still refused).</summary>
    public List<SecurityKey> TrustedKeys { get; }

    public TestIdentityProvider()
    {
        TrustedKeys = [EcKey, RsaKey];
    }

    public static HttpAuthOptions Options(string? staticToken = null) => new()
    {
        Authority = Authority,
        PublicUrl = new Uri(PublicUrl),
        StaticToken = staticToken,
    };

    /// <summary>Registers this provider's keys with No2SQL's JWT scheme.</summary>
    public void Register(IServiceCollection services) =>
        services.Configure<JwtBearerOptions>(HttpAuth.JwtScheme, options =>
        {
            var configuration = new OpenIdConnectConfiguration { Issuer = Authority };
            foreach (var key in TrustedKeys)
            {
                configuration.SigningKeys.Add(key);
            }

            options.Configuration = configuration;
        });

    /// <summary>A token that No2SQL accepts. Each argument changes one thing.</summary>
    public string Token(
        object? audience = null,
        string issuer = Authority,
        string? type = "at+jwt",
        object? scope = null,
        string scopeClaim = "scope",
        DateTime? expires = null,
        DateTime? issuedAt = null,
        SigningCredentials? signing = null)
    {
        var now = issuedAt ?? DateTime.UtcNow;
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "owner",
            ["aud"] = audience ?? McpUrl,
            ["client_id"] = "test-client",
        };
        if (!Equals(scope, string.Empty))
        {
            claims[scopeClaim] = scope ?? "mcp:tools";
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Claims = claims,
            IssuedAt = now,
            NotBefore = now,
            Expires = expires ?? now.AddMinutes(10),
            TokenType = type,
            SigningCredentials = signing ?? new SigningCredentials(EcKey, SecurityAlgorithms.EcdsaSha256),
        };

        return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(descriptor);
    }

    /// <summary>A token with exactly this header and payload, signed ES256 with <see cref="EcKey"/>.</summary>
    public string SignedWithHeader(string headerJson, string payloadJson)
    {
        var signingInput = Base64UrlEncoder.Encode(headerJson) + "." + Base64UrlEncoder.Encode(payloadJson);
        var signature = EcKey.ECDsa.SignData(System.Text.Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256);   // IEEE P1363 (r || s), as JWS needs
        return signingInput + "." + Base64UrlEncoder.Encode(signature);
    }

    /// <summary>The payload of a token No2SQL accepts, as JSON.</summary>
    public static string GoodPayload(DateTime now) => new System.Text.Json.Nodes.JsonObject
    {
        ["iss"] = Authority,
        ["aud"] = McpUrl,
        ["sub"] = "owner",
        ["scope"] = "mcp:tools",
        ["iat"] = new DateTimeOffset(now).ToUnixTimeSeconds(),
        ["exp"] = new DateTimeOffset(now.AddMinutes(10)).ToUnixTimeSeconds(),
    }.ToJsonString();

    /// <summary>A token with header {"alg":"none"} and no signature.</summary>
    public static string UnsignedToken(string payloadJson) =>
        Base64UrlEncoder.Encode("{\"alg\":\"none\",\"typ\":\"at+jwt\"}") + "." + Base64UrlEncoder.Encode(payloadJson) + ".";
}

/// <summary>Collects log lines so tests can check what was (and was not) written.</summary>
internal sealed class CapturedLogs : Microsoft.Extensions.Logging.ILoggerProvider
{
    private readonly List<string> _lines = [];

    public IReadOnlyList<string> Lines { get { lock (_lines) { return [.. _lines]; } } }

    public Microsoft.Extensions.Logging.ILogger CreateLogger(string categoryName) => new Logger(categoryName, this);

    public void Dispose() { }

    private sealed class Logger(string category, CapturedLogs owner) : Microsoft.Extensions.Logging.ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) => true;

        public void Log<TState>(Microsoft.Extensions.Logging.LogLevel logLevel, Microsoft.Extensions.Logging.EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            lock (owner._lines)
            {
                owner._lines.Add($"{logLevel} {category}: {formatter(state, exception)} {exception}");
            }
        }
    }
}
