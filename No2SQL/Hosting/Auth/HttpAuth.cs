using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using No2SQL.Hosting.OAuth;

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

    // The built-in server issues only RFC 9068 access tokens, signed ES256 (threat model R22).
    internal static readonly string[] BuiltinTypes = ["at+jwt", "application/at+jwt"];
    internal static readonly string[] BuiltinAlgorithms = [SecurityAlgorithms.EcdsaSha256];

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

        // The parts of services.AddAuthentication() that are used here. That method also registers ASP.NET
        // Core Data Protection, whose start-up service creates a key ring under the home directory. Nothing
        // here uses Data Protection, and HTTP mode writes no file of its own, so it is left out; and the
        // JWT handler gets an empty configuration, so no configuration source can change how tokens are checked.
        services.AddAuthenticationCore(options =>
        {
            options.DefaultScheme = Scheme;
            options.DefaultChallengeScheme = Scheme;
            options.DefaultForbidScheme = Scheme;
        });
        services.AddWebEncoders();
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IAuthenticationConfigurationProvider, NoAuthenticationConfiguration>();
        var authentication = new AuthenticationBuilder(services)
            .AddScheme<AuthenticationSchemeOptions, BearerAuthenticationHandler>(Scheme, _ => { });

        if (auth.HasAuthority)
        {
            authentication.AddJwtBearer(JwtScheme, options => ConfigureJwt(options, auth));
        }
        else if (auth.Builtin)
        {
            authentication.AddJwtBearer(JwtScheme, options => ConfigureBuiltinJwt(options, auth));
            services.AddNo2SqlOAuthServer(auth);

            // The keys come from the data directory and revoked tokens from the grant store; both notice
            // changes made by the 'No2SQL oauth' commands within a second (R23).
            services.AddOptions<JwtBearerOptions>(JwtScheme)
                .Configure<SigningKeyStore, GrantStore, ILoggerFactory>((options, keys, grants, loggers) =>
                {
                    var log = loggers.CreateLogger("No2SQL.OAuth");
                    options.TokenValidationParameters.IssuerSigningKeyResolver = (_, _, kid, _) => keys.ValidationKeys(kid);
                    options.Events = new JwtBearerEvents
                    {
                        OnTokenValidated = context =>
                        {
                            try
                            {
                                if (context.SecurityToken is not JsonWebToken token || string.IsNullOrEmpty(token.Id) || grants.IsAccessTokenRevoked(token.Id))
                                {
                                    context.Fail(new SecurityTokenRevokedException());
                                }
                            }
                            catch (OAuthDataException ex)
                            {
                                // Fail closed: without the list of revoked tokens, no token is accepted.
                                log.LogError("The revoked tokens could not be read, so every access token is refused: {Reason}", ex.Message);
                                context.Fail(ex);
                            }

                            return Task.CompletedTask;
                        },
                    };
                });
        }

        if (auth.UsesJwt)
        {
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

    /// <summary>
    /// Publishes the protected resource metadata when JWTs are accepted, and the built-in authorization
    /// server's endpoints when it is on.
    /// </summary>
    public static void MapNo2SqlAuthEndpoints(this IEndpointRouteBuilder endpoints, HttpAuthOptions auth)
    {
        if (auth.Builtin)
        {
            endpoints.MapNo2SqlOAuthServer();
        }

        if (auth.ResourceMetadataUrl is null)
        {
            return;
        }

        // Exactly these keys, in this order, from configuration only (never from request headers).
        var body = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["resource"] = auth.McpUrl!,
            ["authorization_servers"] = new[] { auth.Issuer! },
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

        // The RFC 9728 path for the resource <public URL>/mcp, and the root form. Every 401 points clients
        // at the first through resource_metadata. The root form is the last well-known fallback in the MCP
        // authorization spec (2025-11-25 and later) for a client that never saw that header; its "resource"
        // is still <origin>/mcp, the MCP server URL. A strict RFC 9728 client that derived the identifier
        // from the root path would see a mismatch and stop, which fails closed.
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

    // The built-in server: same rules as for an external identity provider, but only ES256 and at+jwt, and the
    // signing keys come from the data directory instead of a metadata document (nothing is fetched).
    private static void ConfigureBuiltinJwt(JwtBearerOptions options, HttpAuthOptions auth)
    {
        options.Configuration = new OpenIdConnectConfiguration { Issuer = auth.Issuer };
        options.MapInboundClaims = false;
        options.SaveToken = false;
        options.IncludeErrorDetails = false;

        var audience = auth.McpUrl!;
        var issuer = auth.Issuer!;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            IssuerValidator = (tokenIssuer, _, _) => string.Equals(tokenIssuer, issuer, StringComparison.Ordinal)
                ? tokenIssuer
                : throw new SecurityTokenInvalidIssuerException("The token issuer is not this server."),
            ValidateAudience = true,
            AudienceValidator = (_, token, _) => HasSingleAudience(token, audience),
            ValidAlgorithms = BuiltinAlgorithms,
            TypeValidator = (type, _, _) => BuiltinTypes.Contains(type, StringComparer.OrdinalIgnoreCase)
                ? type
                : throw new SecurityTokenInvalidTypeException("The token typ is not at+jwt."),
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

        // Expiry first, so an expired token is logged as expired even when its nbf is also wrong.
        if (expires.Value.ToUniversalTime() + ClockSkew < utcNow)
        {
            throw new SecurityTokenExpiredException("The token has expired.") { Expires = expires.Value };
        }

        if (notBefore is { } nbf && nbf > expires)
        {
            throw new SecurityTokenInvalidLifetimeException("The token's not-before time is after its expiry.");
        }

        if (notBefore is { } start && start.ToUniversalTime() - ClockSkew > utcNow)
        {
            throw new SecurityTokenNotYetValidException("The token is not valid yet.") { NotBefore = start };
        }

        return true;
    }

    // "aud" must name the MCP URL and nothing else: one JSON string, or an array of exactly that one
    // string (RFC 7519 4.1.3 makes the two forms equivalent, and some identity providers always write an
    // array). A token for two or more audiences is refused even when the MCP URL is one of them.
    internal static bool HasSingleAudience(SecurityToken token, string expected)
    {
        if (token is not JsonWebToken jwt)
        {
            return false;
        }

        try
        {
            using var payload = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(jwt.EncodedPayload));
            if (!payload.RootElement.TryGetProperty("aud", out var aud))
            {
                return false;
            }

            if (aud.ValueKind == JsonValueKind.Array)
            {
                if (aud.GetArrayLength() != 1)
                {
                    return false;
                }

                aud = aud[0];
            }

            return aud.ValueKind == JsonValueKind.String
                && string.Equals(aud.GetString(), expected, StringComparison.Ordinal);
        }
        catch (Exception ex) when (ex is JsonException or FormatException or ArgumentException)
        {
            return false;
        }
    }
}

/// <summary>An access token of the built-in server that was revoked before its expiry.</summary>
internal sealed class SecurityTokenRevokedException() : SecurityTokenValidationException("The access token was revoked.");

/// <summary>An empty <c>Authentication</c> configuration section: sign-in is configured by the NO2SQL_ variables only.</summary>
internal sealed class NoAuthenticationConfiguration : IAuthenticationConfigurationProvider
{
    public IConfiguration AuthenticationConfiguration { get; } = new ConfigurationBuilder().Build();
}
