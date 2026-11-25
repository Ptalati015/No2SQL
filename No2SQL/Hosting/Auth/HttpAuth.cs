using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace No2SQL.Hosting;

/// <summary>Service registration and endpoints for HTTP-mode sign-in (P2-4).</summary>
internal static class HttpAuth
{
    /// <summary>The scheme every /mcp request is checked with.</summary>
    public const string Scheme = "No2SQL.Bearer";

    /// <summary>The JWT bearer scheme the main scheme hands identity-provider tokens to. Never challenged directly.</summary>
    public const string JwtScheme = "No2SQL.Jwt";

    /// <summary>The authorization policy on /mcp.</summary>
    public const string McpPolicy = "No2SQL.Mcp";

    /// <summary>Who called: "static-token" or "identity-provider". Never the token itself.</summary>
    public const string CallerClaim = "no2sql:caller";

    /// <summary>Present when the caller may use the tools (the static token, or a JWT with the required scope).</summary>
    public const string ScopeGrantedClaim = "no2sql:scope_granted";

    /// <summary>
    /// The caller id that audit lines use (P2-7): the identity provider's <c>sub</c>, or for the static
    /// token "static-token:" and the first 8 hex digits of its SHA-256. Never the token itself.
    /// </summary>
    public const string SubjectClaim = "sub";

    // Asymmetric algorithms only: "none" and every HMAC algorithm are refused.
    internal static readonly string[] AllowedAlgorithms =
    [
        SecurityAlgorithms.RsaSha256, SecurityAlgorithms.RsaSha384, SecurityAlgorithms.RsaSha512,
        SecurityAlgorithms.RsaSsaPssSha256, SecurityAlgorithms.RsaSsaPssSha384, SecurityAlgorithms.RsaSsaPssSha512,
        SecurityAlgorithms.EcdsaSha256, SecurityAlgorithms.EcdsaSha384, SecurityAlgorithms.EcdsaSha512,
    ];

    // RFC 9068 access tokens ("at+jwt", which RFC 7515 lets clients also write as "application/at+jwt")
    // and plain "JWT", which several identity providers still use. Compared case-insensitively (RFC 7515 4.1.9).
    internal static readonly string[] AllowedTypes = ["at+jwt", "application/at+jwt", "JWT"];

    internal static readonly TimeSpan ClockSkew = TimeSpan.FromSeconds(60);

    // A token signed with an unknown key makes the handler fetch the signing keys again, at most this often.
    internal static readonly TimeSpan SigningKeyRefreshInterval = TimeSpan.FromMinutes(5);

    public static void AddNo2SqlHttpAuth(this IServiceCollection services, HttpAuthOptions auth)
    {
        services.AddSingleton(auth);
        if (!auth.RequiresSignIn)
        {
            return;
        }

        var authentication = services
            .AddAuthentication(options =>
            {
                options.DefaultScheme = Scheme;
                options.DefaultChallengeScheme = Scheme;
                options.DefaultForbidScheme = Scheme;
            })
            .AddScheme<AuthenticationSchemeOptions, BearerAuthenticationHandler>(Scheme, _ => { });

        if (auth.HasAuthority)
        {
            authentication.AddJwtBearer(JwtScheme, options => ConfigureJwt(options, auth));

            // The clock for token lifetimes comes from DI, so tests can move it.
            services.AddOptions<JwtBearerOptions>(JwtScheme)
                .Configure<TimeProvider>((options, clock) => options.TokenValidationParameters.LifetimeValidator =
                    (notBefore, expires, _, _) => ValidateLifetime(notBefore, expires, clock.GetUtcNow().UtcDateTime));
        }

        services.AddAuthorizationBuilder().AddPolicy(McpPolicy, policy => policy
            .AddAuthenticationSchemes(Scheme)
            .RequireAuthenticatedUser()
            .RequireClaim(ScopeGrantedClaim, "true"));
    }

    /// <summary>Publishes the protected resource metadata when an identity provider is configured.</summary>
    public static void MapNo2SqlAuthEndpoints(this IEndpointRouteBuilder endpoints, HttpAuthOptions auth)
    {
        if (auth.ResourceMetadataUrl is null)
        {
            return;
        }

        // Exactly these keys, in this order, from configuration only (never from request headers).
        var body = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["resource"] = auth.McpUrl!,
            ["authorization_servers"] = new[] { auth.Authority! },
            ["scopes_supported"] = new[] { auth.Scope },
            ["bearer_methods_supported"] = new[] { "header" },
            ["resource_name"] = "No2SQL",
        });

        RequestDelegate metadata = context =>
        {
            context.Response.ContentType = "application/json";
            context.Response.Headers.CacheControl = "no-store";
            return context.Response.WriteAsync(body);
        };

        // The RFC 9728 path for the resource <public URL>/mcp, and the root form some clients try first.
        endpoints.MapGet(HttpAuthOptions.ResourceMetadataPath, metadata);
        endpoints.MapGet("/.well-known/oauth-protected-resource", metadata);
    }

    /// <summary>The <see cref="SubjectClaim"/> of a static-token caller: a fingerprint, not the token.</summary>
    public static string StaticTokenSubject(byte[] tokenHash) => "static-token:" + Convert.ToHexStringLower(tokenHash.AsSpan(0, 4));

    /// <summary>The scopes in a validated JWT: "scope" (space-separated, RFC 9068) or "scp" (string or array).</summary>
    public static IEnumerable<string> GrantedScopes(ClaimsPrincipal principal) =>
        principal.Claims
            .Where(c => c.Type is "scope" or "scp")
            .SelectMany(c => c.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries));

    private static void ConfigureJwt(JwtBearerOptions options, HttpAuthOptions auth)
    {
        options.Authority = auth.Authority;
        options.RequireHttpsMetadata = true;       // metadata and signing keys over https only
        options.MapInboundClaims = false;
        options.SaveToken = false;
        options.IncludeErrorDetails = false;
        options.RefreshOnIssuerKeyNotFound = true;
        options.RefreshInterval = SigningKeyRefreshInterval;
        options.BackchannelTimeout = TimeSpan.FromSeconds(10);

        var audience = auth.McpUrl!;
        var issuer = auth.Authority!;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            IssuerValidator = (tokenIssuer, _, _) => string.Equals(tokenIssuer, issuer, StringComparison.Ordinal)
                ? tokenIssuer
                : throw new SecurityTokenInvalidIssuerException("The token issuer is not the configured authority."),
            ValidateAudience = true,
            AudienceValidator = (_, token, _) => HasSingleAudience(token, audience),
            ValidAlgorithms = AllowedAlgorithms,
            TypeValidator = (type, _, _) => AllowedTypes.Contains(type, StringComparer.OrdinalIgnoreCase)
                ? type
                : throw new SecurityTokenInvalidTypeException("The token typ is not allowed."),
            ValidateLifetime = true,
            RequireExpirationTime = true,
            RequireSignedTokens = true,
            ValidateIssuerSigningKey = true,
            ClockSkew = ClockSkew,
        };
    }

    // exp is required; exp and nbf are checked against the injected clock with ClockSkew either way.
    internal static bool ValidateLifetime(DateTime? notBefore, DateTime? expires, DateTime utcNow)
    {
        if (expires is null)
        {
            throw new SecurityTokenNoExpirationException("The token has no expiry.");
        }

        if (notBefore is { } nbf && nbf > expires)
        {
            throw new SecurityTokenInvalidLifetimeException("The token's not-before time is after its expiry.");
        }

        if (notBefore is { } start && start.ToUniversalTime() - ClockSkew > utcNow)
        {
            throw new SecurityTokenNotYetValidException("The token is not valid yet.") { NotBefore = start };
        }

        if (expires.Value.ToUniversalTime() + ClockSkew < utcNow)
        {
            throw new SecurityTokenExpiredException("The token has expired.") { Expires = expires.Value };
        }

        return true;
    }

    // "aud" must be one JSON string equal to the MCP URL. An array, even one that contains it, is refused.
    internal static bool HasSingleAudience(SecurityToken token, string expected)
    {
        if (token is not JsonWebToken jwt)
        {
            return false;
        }

        try
        {
            using var payload = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(jwt.EncodedPayload));
            return payload.RootElement.TryGetProperty("aud", out var aud)
                && aud.ValueKind == JsonValueKind.String
                && string.Equals(aud.GetString(), expected, StringComparison.Ordinal);
        }
        catch (Exception ex) when (ex is JsonException or FormatException or ArgumentException)
        {
            return false;
        }
    }
}
