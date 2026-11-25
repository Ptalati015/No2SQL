using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;

namespace No2SQL.Hosting;

/// <summary>
/// The one authentication scheme of HTTP mode. It reads only the <c>Authorization: Bearer</c> header
/// (never a query string, form field or cookie), accepts the static <c>NO2SQL_HTTP_TOKEN</c> by a
/// constant-time comparison, hands any other token to the JWT scheme when an identity provider is
/// configured, and writes every 401 and 403 itself so the answers are exactly the ones in the spec.
/// </summary>
internal sealed class BearerAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory loggerFactory,
    UrlEncoder encoder,
    HttpAuthOptions auth)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, loggerFactory, encoder)
{
    // Longer than any real access token; anything bigger is refused before it is parsed.
    private const int MaxTokenLength = 8192;

    private static readonly object FailureKey = new();

    private readonly ILogger _log = loggerFactory.CreateLogger("No2SQL.Auth");

    // Longest identity-provider "sub" copied onto the caller; anything longer or with control characters is not.
    private const int MaxSubjectLength = 256;

    // Hash of the static token, so the comparison takes the same time whatever the presented length.
    private readonly byte[]? _staticTokenHash = auth.StaticToken is null ? null : SHA256.HashData(Encoding.UTF8.GetBytes(auth.StaticToken));

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var headers = Request.Headers.Authorization;
        if (StringValues.IsNullOrEmpty(headers))
        {
            return Remember(AuthenticateResult.NoResult(), null);
        }

        if (headers.Count != 1 || !TryReadBearerToken(headers[0]!, out var token))
        {
            return Remember(AuthenticateResult.NoResult(), "the Authorization header is not a single 'Bearer <token>'");
        }

        if (_staticTokenHash is not null
            && CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(token)), _staticTokenHash))
        {
            var identity = new ClaimsIdentity(
                [
                    new Claim(HttpAuth.CallerClaim, "static-token"),
                    new Claim(HttpAuth.SubjectClaim, HttpAuth.StaticTokenSubject(_staticTokenHash)),
                    new Claim(HttpAuth.ScopeGrantedClaim, "true"),
                ],
                Scheme.Name);
            return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name));
        }

        if (!auth.HasAuthority)
        {
            return Remember(AuthenticateResult.Fail("invalid token"), "the token is not NO2SQL_HTTP_TOKEN");
        }

        var jwt = await Context.AuthenticateAsync(HttpAuth.JwtScheme);
        if (!jwt.Succeeded || jwt.Principal is null)
        {
            return Remember(AuthenticateResult.Fail("invalid token"), DescribeJwtFailure(jwt.Failure));
        }

        var subject = jwt.Principal.FindFirst(HttpAuth.SubjectClaim)?.Value;
        var claims = new List<Claim>
        {
            new(HttpAuth.CallerClaim, "identity-provider"),
            new(HttpAuth.SubjectClaim, IsUsableSubject(subject) ? subject : "identity-provider"),
        };
        if (HttpAuth.GrantedScopes(jwt.Principal).Contains(auth.Scope, StringComparer.Ordinal))
        {
            claims.Add(new Claim(HttpAuth.ScopeGrantedClaim, "true"));
        }

        var caller = new ClaimsPrincipal(new ClaimsIdentity(claims, Scheme.Name));
        return AuthenticateResult.Success(new AuthenticationTicket(caller, Scheme.Name));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        var failure = Context.Items.TryGetValue(FailureKey, out var reason) ? reason as string : null;
        var ip = Context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        if (failure is null)
        {
            _log.LogInformation("401 for {ClientIp}: no bearer token.", ip);
        }
        else
        {
            _log.LogWarning("401 for {ClientIp}: {Reason}.", ip, failure);
        }

        // RFC 6750 section 3: no error code when the request had no token at all.
        var parameters = new List<string>();
        if (failure is not null && Request.Headers.Authorization.Count > 0
            && Request.Headers.Authorization[0]!.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            parameters.Add("error=\"invalid_token\"");
        }

        AddDiscovery(parameters);
        return Answer(401, parameters);
    }

    protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        _log.LogWarning("403 for {ClientIp}: the token does not carry the scope {Scope}.",
            Context.Connection.RemoteIpAddress?.ToString() ?? "unknown", auth.Scope);

        List<string> parameters = ["error=\"insufficient_scope\""];
        AddDiscovery(parameters);
        return Answer(403, parameters);
    }

    // resource_metadata and scope only when there is an authorization server to discover.
    private void AddDiscovery(List<string> parameters)
    {
        if (auth.ResourceMetadataUrl is { } metadata)
        {
            parameters.Add($"resource_metadata=\"{metadata}\"");
            parameters.Add($"scope=\"{auth.Scope}\"");
        }
    }

    private Task Answer(int status, List<string> parameters)
    {
        Response.StatusCode = status;
        Response.Headers.WWWAuthenticate = parameters.Count == 0 ? "Bearer" : "Bearer " + string.Join(", ", parameters);
        Response.Headers.CacheControl = "no-store";
        return Task.CompletedTask;   // empty body: nothing from the request is echoed
    }

    private AuthenticateResult Remember(AuthenticateResult result, string? reason)
    {
        if (reason is not null)
        {
            Context.Items[FailureKey] = reason;
        }

        return result;
    }

    // "Bearer" (any case), one or more spaces, then an RFC 6750 b64token.
    private static bool TryReadBearerToken(string header, out string token)
    {
        token = string.Empty;
        const string prefix = "Bearer ";
        if (header.Length > prefix.Length + MaxTokenLength || !header.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var candidate = header[prefix.Length..].TrimStart(' ');
        if (candidate.Length == 0 || !IsB64Token(candidate))
        {
            return false;
        }

        token = candidate;
        return true;
    }

    private static bool IsB64Token(string value)
    {
        var end = value.Length;
        while (end > 0 && value[end - 1] == '=')
        {
            end--;
        }

        if (end == 0)
        {
            return false;
        }

        for (var i = 0; i < end; i++)
        {
            var c = value[i];
            if (!(char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_' or '~' or '+' or '/'))
            {
                return false;
            }
        }

        return true;
    }

    // The identity provider's "sub" goes into audit lines, so only short printable values are kept.
    private static bool IsUsableSubject([System.Diagnostics.CodeAnalysis.NotNullWhen(true)] string? subject) =>
        subject is { Length: > 0 and <= MaxSubjectLength } && !subject.Any(char.IsControl);

    // A fixed reason per failure kind. The exception message is never used: it can quote token parts.
    private static string DescribeJwtFailure(Exception? failure) => failure switch
    {
        null => "the identity provider token was not accepted",
        SecurityTokenExpiredException => "the access token has expired",
        SecurityTokenNotYetValidException => "the access token is not valid yet",
        SecurityTokenInvalidAudienceException => "the access token is for another audience",
        SecurityTokenInvalidIssuerException => "the access token is from another issuer",
        SecurityTokenSignatureKeyNotFoundException => "the access token is signed with an unknown key",
        SecurityTokenInvalidSignatureException => "the access token signature is invalid",
        SecurityTokenInvalidAlgorithmException => "the access token uses an algorithm that is not allowed",
        SecurityTokenInvalidTypeException => "the access token has the wrong typ",
        SecurityTokenNoExpirationException => "the access token has no expiry",
        SecurityTokenInvalidLifetimeException => "the access token has an invalid lifetime",
        SecurityTokenMalformedException => "the access token is malformed",
        InvalidOperationException => "the identity provider's metadata or signing keys could not be loaded",
        HttpRequestException or IOException or TaskCanceledException => "the identity provider could not be reached",
        _ => "the access token was rejected (" + failure.GetType().Name + ")",
    };
}
