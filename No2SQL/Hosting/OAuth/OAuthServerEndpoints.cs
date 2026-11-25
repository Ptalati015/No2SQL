using System.Globalization;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

namespace No2SQL.Hosting.OAuth;

/// <summary>
/// The built-in authorization server's endpoints (P2-5). Every URL they publish comes from
/// <c>NO2SQL_PUBLIC_URL</c>, never from a request header (R1). Every response carries
/// <c>Cache-Control: no-store</c>; every failure is a fixed RFC 6749 or RFC 7591 code with a fixed description.
/// </summary>
internal static partial class OAuthServerEndpoints
{
    public const string AuthorizationServerMetadataPath = "/.well-known/oauth-authorization-server";
    public const string JwksPath = "/jwks";
    public const string RegisterPath = "/register";
    public const string AuthorizePath = "/authorize";
    public const string LoginPath = "/login";
    public const string ConsentPath = "/consent";
    public const string TokenPath = "/token";

    /// <summary>The owner session cookie (R16).</summary>
    public const string SessionCookie = "__Host-no2sql_owner";

    /// <summary>The fixed scope list (R2, R12).</summary>
    public static readonly string[] Scopes = ["mcp:tools", "offline_access"];

    public const string DefaultScope = "mcp:tools";
    public const int MaxBodyBytes = 16 * 1024;
    public const int MaxParameterLength = 2048;
    public const int MaxQueryLength = 8192;

    private static readonly Dictionary<string, string> Descriptions = new(StringComparer.Ordinal)
    {
        ["invalid_request"] = "The request is missing a required parameter, repeats one, or has one that is not allowed.",
        ["invalid_client"] = "The client is not known.",
        ["invalid_grant"] = "The authorization code or refresh token is invalid, expired, used or was issued to another client.",
        ["unauthorized_client"] = "The client may not use this grant type.",
        ["unsupported_grant_type"] = "Only authorization_code and refresh_token are supported.",
        ["unsupported_response_type"] = "Only response_type=code is supported.",
        ["invalid_scope"] = "The requested scope is not one of mcp:tools and offline_access, or is more than was granted.",
        ["invalid_target"] = "The resource parameter must be the MCP endpoint of this server.",
        ["access_denied"] = "The owner denied the request.",
        ["server_error"] = "The server could not complete the request.",
        ["invalid_client_metadata"] = "The registration has a field that is missing or not supported.",
        ["invalid_redirect_uri"] = "Redirect URIs must be https:// without a fragment or user info, or http:// to 127.0.0.1, [::1] or localhost.",
    };

    public static void MapNo2SqlOAuthServer(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet(AuthorizationServerMetadataPath, Guard(ErrorStyle.Json, (context, server) => WriteJson(context, 200, server.MetadataJson)));
        endpoints.MapGet(JwksPath, Guard(ErrorStyle.Json, (context, server) => WriteJson(context, 200, server.Keys.JwksJson())));
        endpoints.MapPost(RegisterPath, Guard(ErrorStyle.Json, RegisterAsync));
        endpoints.MapGet(AuthorizePath, Guard(ErrorStyle.Html, AuthorizeAsync));
        endpoints.MapPost(LoginPath, Guard(ErrorStyle.Html, LoginAsync));
        endpoints.MapPost(ConsentPath, Guard(ErrorStyle.Html, ConsentAsync));
        endpoints.MapPost(TokenPath, Guard(ErrorStyle.Json, TokenAsync));
        endpoints.MapGet(OAuthPages.StylePath, static context =>
        {
            context.Response.ContentType = "text/css; charset=utf-8";
            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers.XContentTypeOptions = "nosniff";
            return context.Response.WriteAsync(OAuthPages.Stylesheet);
        });
    }

    internal enum ErrorStyle
    {
        Json,
        Html,
    }

    /// <summary>
    /// Runs an endpoint and turns an unexpected exception into <c>server_error</c> with an error id that is
    /// logged with the exception (R24). Internal so the test host can prove it with a throwing endpoint.
    /// </summary>
    internal static RequestDelegate Guard(ErrorStyle style, Func<HttpContext, OAuthServer, Task> endpoint) => async context =>
    {
        var server = context.RequestServices.GetRequiredService<OAuthServer>();
        try
        {
            await endpoint(context, server);
        }
        catch (Exception ex) when (!context.Response.HasStarted && !context.RequestAborted.IsCancellationRequested)
        {
            var errorId = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(6));
            server.Log.LogError(ex, "{Path} failed for {ClientIp}; error id {ErrorId}.", context.Request.Path.Value, ClientIp(context), errorId);
            context.Response.Clear();
            if (style == ErrorStyle.Json)
            {
                await WriteError(context, 500, "server_error");
            }
            else
            {
                await WritePage(context, 500, OAuthPages.Error($"Something went wrong on the server (error id {errorId})."), null);
            }
        }
    };

    // RFC 7591 Dynamic Client Registration (R4 to R7).
    private static async Task RegisterAsync(HttpContext context, OAuthServer server)
    {
        var ip = ClientIp(context);
        if (!server.RegisterLimit.TryAcquire(ip, out var retryAfter))
        {
            server.Log.LogWarning("Registration from {ClientIp} refused: more than 10 in an hour.", ip);
            await TooManyRequests(context, retryAfter);
            return;
        }

        if (!HasMediaType(context, "application/json"))
        {
            await Status(context, 415);
            return;
        }

        var body = await ReadBodyAsync(context);
        if (body is null)
        {
            await Status(context, 413);
            return;
        }

        if (!TryReadRegistration(body, out var name, out var redirectUris, out var error))
        {
            server.Log.LogInformation("Registration from {ClientIp} refused: {Error}.", ip, error);
            await WriteError(context, 400, error);
            return;
        }

        var client = server.Clients.Register(name, redirectUris);
        if (client is null)
        {
            server.Log.LogWarning("Registration from {ClientIp} refused: {Max} clients are stored and all are approved.", ip, server.Clients.MaxClients);
            await TooManyRequests(context, TimeSpan.FromHours(1));
            return;
        }

        server.Log.LogInformation("Registered client {ClientId} from {ClientIp}, redirecting to {RedirectHosts}.",
            client.ClientId, ip, string.Join(", ", redirectUris.Select(RedirectUriRules.Describe).Distinct()));

        await WriteJson(context, 201, JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["client_id"] = client.ClientId,
            ["client_id_issued_at"] = client.CreatedAt.ToUnixTimeSeconds(),
            ["redirect_uris"] = client.RedirectUris,
            ["token_endpoint_auth_method"] = "none",
            ["grant_types"] = new[] { "authorization_code", "refresh_token" },
            ["response_types"] = new[] { "code" },
        }));
    }

    // Keeps only client_name and redirect_uris; refuses anything that asks for a secret or another grant (R5, R7).
    private static bool TryReadRegistration(byte[] body, out string? name, out List<string> redirectUris, out string error)
    {
        name = null;
        redirectUris = [];
        error = "invalid_client_metadata";
        try
        {
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            if (root.TryGetProperty("token_endpoint_auth_method", out var method)
                && (method.ValueKind != JsonValueKind.String || method.GetString() != "none"))
            {
                return false;
            }

            if (!AllIn(root, "grant_types", ["authorization_code", "refresh_token"], mustContain: "authorization_code")
                || !AllIn(root, "response_types", ["code"], mustContain: "code"))
            {
                return false;
            }

            if (!root.TryGetProperty("redirect_uris", out var uris) || uris.ValueKind != JsonValueKind.Array
                || uris.GetArrayLength() is 0 or > RedirectUriRules.MaxCount)
            {
                error = "invalid_redirect_uri";
                return false;
            }

            foreach (var entry in uris.EnumerateArray())
            {
                var value = entry.ValueKind == JsonValueKind.String ? entry.GetString() : null;
                if (!RedirectUriRules.IsAcceptable(value))
                {
                    error = "invalid_redirect_uri";
                    return false;
                }

                redirectUris.Add(value!);
            }

            if (root.TryGetProperty("client_name", out var clientName))
            {
                if (clientName.ValueKind != JsonValueKind.String)
                {
                    return false;
                }

                name = ClientNames.Clean(clientName.GetString());
            }

            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    // An optional array member whose strings all come from the allowed list and include mustContain.
    private static bool AllIn(JsonElement root, string member, string[] allowed, string mustContain)
    {
        if (!root.TryGetProperty(member, out var array))
        {
            return true;
        }

        if (array.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        var values = array.EnumerateArray().Select(e => e.ValueKind == JsonValueKind.String ? e.GetString() : null).ToList();
        return values.All(v => v is not null && allowed.Contains(v)) && values.Contains(mustContain);
    }

    // The authorization endpoint (R11 to R13). The client and redirect URI are checked before anything else;
    // until both are valid every error is a page, never a redirect.
    private static async Task AuthorizeAsync(HttpContext context, OAuthServer server)
    {
        var raw = context.Request.QueryString.Value ?? "";
        if (raw.Length > MaxQueryLength)
        {
            await WritePage(context, 400, OAuthPages.Error("The request is too large."), null);
            return;
        }

        var query = QueryHelpers.ParseQuery(raw);
        if (!TrySingle(query, "client_id", out var clientId) || clientId is null
            || !TrySingle(query, "redirect_uri", out var redirectUri) || redirectUri is null)
        {
            await WritePage(context, 400, OAuthPages.Error("The request does not name a client and a redirect address."), null);
            return;
        }

        var client = await server.ResolveClientAsync(clientId, context.RequestAborted);
        if (client is null)
        {
            server.Log.LogWarning("Authorization request from {ClientIp} refused: unknown client.", ClientIp(context));
            await WritePage(context, 400, OAuthPages.Error("This application is not registered with this No2SQL server."), null);
            return;
        }

        if (!client.Allows(redirectUri))
        {
            server.Log.LogWarning("Authorization request from {ClientIp} for client {ClientId} refused: redirect address not registered.", ClientIp(context), client.ClientId);
            await WritePage(context, 400, OAuthPages.Error("The address this application asked to return to is not registered for it."), null);
            return;
        }

        // From here the redirect URI is trusted, so errors go back to the client.
        if (!TrySingle(query, "state", out var state) || query.Any(p => p.Value.Count > 1 || p.Value.Any(v => v is { Length: > MaxParameterLength })))
        {
            RedirectError(context, redirectUri, "invalid_request", state);
            return;
        }

        TrySingle(query, "response_type", out var responseType);
        TrySingle(query, "code_challenge", out var challenge);
        TrySingle(query, "code_challenge_method", out var challengeMethod);
        TrySingle(query, "resource", out var resource);
        TrySingle(query, "scope", out var scopeParameter);

        string? error = null;
        if (responseType != "code")
        {
            error = "unsupported_response_type";
        }
        else if (challengeMethod != "S256" || challenge is null || !PkceValue().IsMatch(challenge))
        {
            error = "invalid_request";
        }
        else if (!server.IsMcpResource(resource))
        {
            error = "invalid_target";
        }

        var scope = DefaultScope;
        if (error is null && scopeParameter is not null)
        {
            var requested = scopeParameter.Split(' ', StringSplitOptions.RemoveEmptyEntries).Distinct(StringComparer.Ordinal).ToList();
            if (requested.Count == 0 || requested.Any(s => !Scopes.Contains(s)))
            {
                error = "invalid_scope";
            }
            else
            {
                scope = string.Join(' ', requested);
            }
        }

        if (error is not null)
        {
            server.Log.LogInformation("Authorization request for client {ClientId} refused: {Error}.", client.ClientId, error);
            RedirectError(context, redirectUri, error, state);
            return;
        }

        var session = SessionFrom(context, server);
        var pending = server.Interactions.Add(client, redirectUri, challenge!, scope, server.McpUrl, state, session);
        if (session is null)
        {
            await WritePage(context, 200, OAuthPages.Login(pending, null), pending.RedirectUri);
            return;
        }

        await ContinueAfterLoginAsync(context, server, pending);
    }

    // The owner's password (R14, R16, R17).
    private static async Task LoginAsync(HttpContext context, OAuthServer server)
    {
        var form = await ReadFormAsync(context, server);
        if (form is null)
        {
            return;
        }

        var pending = server.Interactions.Find(Single(form, "request"));
        if (pending is null)
        {
            await WritePage(context, 400, OAuthPages.Error("This sign-in request has expired."), null);
            return;
        }

        if (!SecretEquals(Single(form, "csrf"), pending.LoginToken))
        {
            await WritePage(context, 403, OAuthPages.Error("The sign-in form was not sent from this page."), null);
            return;
        }

        var ip = ClientIp(context);
        var (refused, delay, attempt) = server.Throttle.Begin(ip);
        if (refused)
        {
            server.Log.LogWarning("Owner login from {ClientIp} refused without checking: too many wrong passwords in the last hour.", ip);
            await WritePage(context, 429, OAuthPages.Error("Too many wrong passwords. Try again later."), null);
            return;
        }

        if (delay > TimeSpan.Zero)
        {
            await Task.Delay(delay, server.Clock, context.RequestAborted);
        }

        if (!server.Owner.Verify(Single(form, "password")))
        {
            server.Log.LogWarning("Owner login failed from {ClientIp}.", ip);
            await WritePage(context, 401, OAuthPages.Login(pending, "That password is not correct."), pending.RedirectUri);
            return;
        }

        server.Throttle.Succeeded(ip, attempt);
        var session = server.Interactions.StartSession();
        pending.SessionId = session;
        context.Response.Headers.Append("Set-Cookie",
            $"{SessionCookie}={session}; Path=/; Max-Age={(int)InteractionStore.Lifetime.TotalSeconds}; Secure; HttpOnly; SameSite=Strict");
        server.Log.LogInformation("Owner signed in from {ClientIp}.", ip);

        await ContinueAfterLoginAsync(context, server, pending);
    }

    // Consent (R13, R17): POST only, with the session cookie, the anti-forgery token of this request and this session, and our Origin.
    private static async Task ConsentAsync(HttpContext context, OAuthServer server)
    {
        var form = await ReadFormAsync(context, server);
        if (form is null)
        {
            return;
        }

        var session = SessionFrom(context, server);
        var pending = server.Interactions.Find(Single(form, "request"));
        if (session is null || pending is null || pending.SessionId is null
            || !SecretEquals(session, pending.SessionId) || !SecretEquals(Single(form, "csrf"), pending.ConsentToken))
        {
            server.Log.LogWarning("Consent from {ClientIp} refused: no matching sign-in session or anti-forgery token.", ClientIp(context));
            await WritePage(context, 403, OAuthPages.Error("This approval was not sent from your sign-in page, or your sign-in has expired."), null);
            return;
        }

        if (!server.Interactions.Remove(pending.Id))
        {
            await WritePage(context, 400, OAuthPages.Error("This request was already answered."), null);
            return;
        }

        switch (Single(form, "decision"))
        {
            case "approve":
                Approve(context, server, pending);
                return;
            case "deny":
                server.Log.LogInformation("Owner denied client {ClientId}.", pending.Client.ClientId);
                RedirectError(context, pending.RedirectUri, "access_denied", pending.State, StatusCodes.Status303SeeOther);
                return;
            default:
                await WritePage(context, 400, OAuthPages.Error("Choose Approve or Deny."), null);
                return;
        }
    }

    // After login: a CIMD client the owner approved for this redirect URI in the last 30 days skips the consent page.
    private static async Task ContinueAfterLoginAsync(HttpContext context, OAuthServer server, PendingAuthorization pending)
    {
        if (pending.Client.IsMetadataDocument && server.Clients.HasRecentApproval(pending.Client.ClientId, pending.RedirectUri)
            && server.Interactions.Remove(pending.Id))
        {
            server.Log.LogInformation("Client {ClientId} re-approved from the owner's approval of the last 30 days.", pending.Client.ClientId);
            Approve(context, server, pending);
            return;
        }

        await WritePage(context, 200, OAuthPages.Consent(pending), pending.RedirectUri);
    }

    private static void Approve(HttpContext context, OAuthServer server, PendingAuthorization pending)
    {
        server.Clients.RecordApproval(pending.Client.ClientId, pending.RedirectUri, pending.Client.IsMetadataDocument);
        var code = server.Codes.Issue(pending.Client.ClientId, pending.RedirectUri, pending.CodeChallenge, pending.Scope, pending.Resource);
        server.Log.LogInformation("Owner approved client {ClientId} for {RedirectHost}.", pending.Client.ClientId, RedirectUriRules.Describe(pending.RedirectUri));

        var parameters = new List<KeyValuePair<string, string?>> { new("code", code) };
        if (pending.State is not null)
        {
            parameters.Add(new("state", pending.State));
        }

        Redirect(context, pending.RedirectUri, parameters, StatusCodes.Status303SeeOther);
    }

    // The token endpoint (R19 to R22).
    private static async Task TokenAsync(HttpContext context, OAuthServer server)
    {
        var ip = ClientIp(context);
        if (!server.TokenLimit.TryAcquire(ip, out var retryAfter))
        {
            server.Log.LogWarning("Token request from {ClientIp} refused: more than 30 in a minute.", ip);
            await TooManyRequests(context, retryAfter);
            return;
        }

        if (!HasMediaType(context, "application/x-www-form-urlencoded"))
        {
            await Status(context, 415);
            return;
        }

        var body = await ReadBodyAsync(context);
        if (body is null)
        {
            await Status(context, 413);
            return;
        }

        var form = ParseForm(body);
        if (form is null || form.Any(p => p.Value.Count > 1))
        {
            await WriteError(context, 400, "invalid_request");
            return;
        }

        var resource = Single(form, "resource");
        if (resource is not null && !server.IsMcpResource(resource))
        {
            await WriteError(context, 400, "invalid_target");
            return;
        }

        switch (Single(form, "grant_type"))
        {
            case "authorization_code":
                await ExchangeCodeAsync(context, server, form);
                return;
            case "refresh_token":
                await RefreshAsync(context, server, form);
                return;
            case null:
                await WriteError(context, 400, "invalid_request");
                return;
            default:
                await WriteError(context, 400, "unsupported_grant_type");
                return;
        }
    }

    private static async Task ExchangeCodeAsync(HttpContext context, OAuthServer server, Dictionary<string, StringValues> form)
    {
        var code = Single(form, "code");
        var clientId = Single(form, "client_id");
        var redirectUri = Single(form, "redirect_uri");
        var verifier = Single(form, "code_verifier");
        if (code is null || clientId is null || redirectUri is null || verifier is null)
        {
            await WriteError(context, 400, "invalid_request");
            return;
        }

        // A malformed verifier is answered like a wrong one: invalid_grant, after the same work.
        var redemption = server.Codes.Redeem(code, clientId, redirectUri, PkceValue().IsMatch(verifier) ? verifier : "");
        if (redemption.ReusedFamily is { } family)
        {
            server.Grants.RevokeFamily(family);
            server.Log.LogWarning("Authorization code presented again by {ClientIp}; the tokens issued from it are revoked.", ClientIp(context));
            await WriteError(context, 400, "invalid_grant");
            return;
        }

        if (!redemption.Ok || redemption.Record is not { } record || !PkceValue().IsMatch(verifier))
        {
            server.Log.LogInformation("Code exchange from {ClientIp} refused: invalid_grant.", ClientIp(context));
            await WriteError(context, 400, "invalid_grant");
            return;
        }

        var (jti, issuedAt, expires) = server.Tokens.Next();
        var refreshToken = server.Grants.CreateGrant(record.Family!, record.ClientId, record.Scope, jti, expires);
        if (refreshToken is null)
        {
            await WriteError(context, 400, "invalid_grant");
            return;
        }

        var accessToken = server.Tokens.Create(jti, issuedAt, expires, record.ClientId, record.Scope);
        server.Log.LogInformation("Tokens issued to client {ClientId} for an authorization code.", record.ClientId);
        await WriteTokens(context, accessToken, expires - issuedAt, refreshToken, record.Scope);
    }

    private static async Task RefreshAsync(HttpContext context, OAuthServer server, Dictionary<string, StringValues> form)
    {
        var token = Single(form, "refresh_token");
        var clientId = Single(form, "client_id");
        if (token is null || clientId is null)
        {
            await WriteError(context, 400, "invalid_request");
            return;
        }

        var requested = Single(form, "scope")?.Split(' ', StringSplitOptions.RemoveEmptyEntries).Distinct(StringComparer.Ordinal).ToList();
        var (jti, issuedAt, expires) = server.Tokens.Next();
        var result = server.Grants.Refresh(token, clientId, requested, jti, expires);
        switch (result.Outcome)
        {
            case RefreshOutcome.Rotated:
                var accessToken = server.Tokens.Create(jti, issuedAt, expires, clientId, result.Scope!);
                server.Log.LogInformation("Tokens refreshed for client {ClientId}.", clientId);
                await WriteTokens(context, accessToken, expires - issuedAt, result.RefreshToken!, result.Scope!);
                return;
            case RefreshOutcome.Reused:
                server.Log.LogWarning("A used refresh token of client {ClientId} was presented by {ClientIp}; its family is revoked.", result.ClientId, ClientIp(context));
                await WriteError(context, 400, "invalid_grant");
                return;
            case RefreshOutcome.ScopeRefused:
                await WriteError(context, 400, "invalid_scope");
                return;
            default:
                server.Log.LogInformation("Refresh from {ClientIp} refused: invalid_grant.", ClientIp(context));
                await WriteError(context, 400, "invalid_grant");
                return;
        }
    }

    private static Task WriteTokens(HttpContext context, string accessToken, TimeSpan lifetime, string refreshToken, string scope) =>
        WriteJson(context, 200, JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["access_token"] = accessToken,
            ["token_type"] = "Bearer",
            ["expires_in"] = (long)lifetime.TotalSeconds,
            ["refresh_token"] = refreshToken,
            ["scope"] = scope,
        }));

    // Reads and checks a login or consent form: our Origin (or Referer), form-encoded, at most 16 KiB, no repeated fields.
    private static async Task<Dictionary<string, StringValues>?> ReadFormAsync(HttpContext context, OAuthServer server)
    {
        if (!server.IsSameOrigin(context.Request))
        {
            server.Log.LogWarning("{Path} from {ClientIp} refused: the request did not come from this server's pages.", context.Request.Path.Value, ClientIp(context));
            await WritePage(context, 403, OAuthPages.Error("This form was not sent from this server's sign-in page."), null);
            return null;
        }

        if (!HasMediaType(context, "application/x-www-form-urlencoded"))
        {
            await Status(context, 415);
            return null;
        }

        var body = await ReadBodyAsync(context);
        if (body is null)
        {
            await Status(context, 413);
            return null;
        }

        var form = ParseForm(body);
        if (form is null || form.Any(p => p.Value.Count > 1 || p.Value.Any(v => v is { Length: > MaxParameterLength })))
        {
            await WritePage(context, 400, OAuthPages.Error("The form is not valid."), null);
            return null;
        }

        return form;
    }

    private static Dictionary<string, StringValues>? ParseForm(byte[] body)
    {
        try
        {
            return new FormReader(Encoding.UTF8.GetString(body)).ReadForm();
        }
        catch (InvalidDataException)
        {
            return null;
        }
    }

    // The body, or null when it is larger than 16 KiB.
    private static async Task<byte[]?> ReadBodyAsync(HttpContext context)
    {
        if (context.Request.ContentLength > MaxBodyBytes)
        {
            return null;
        }

        var buffer = new byte[MaxBodyBytes + 1];
        var total = 0;
        int read;
        while ((read = await context.Request.Body.ReadAsync(buffer.AsMemory(total), context.RequestAborted)) > 0)
        {
            total += read;
            if (total > MaxBodyBytes)
            {
                return null;
            }
        }

        return buffer[..total];
    }

    private static bool HasMediaType(HttpContext context, string mediaType) =>
        MediaTypeHeaderValue.TryParse(context.Request.ContentType, out var parsed)
        && string.Equals(parsed.MediaType, mediaType, StringComparison.OrdinalIgnoreCase);

    private static string? SessionFrom(HttpContext context, OAuthServer server) =>
        context.Request.Cookies.TryGetValue(SessionCookie, out var id) && server.Interactions.IsSession(id) ? id : null;

    private static bool TrySingle(Dictionary<string, StringValues> parameters, string name, out string? value)
    {
        value = null;
        if (!parameters.TryGetValue(name, out var values))
        {
            return true;
        }

        if (values.Count != 1 || values[0] is not { Length: <= MaxParameterLength } single)
        {
            return false;
        }

        value = single;
        return true;
    }

    private static string? Single(Dictionary<string, StringValues> parameters, string name) =>
        parameters.TryGetValue(name, out var values) && values.Count == 1 ? values[0] : null;

    private static bool SecretEquals(string? presented, string expected) =>
        presented is not null && CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(presented), Encoding.UTF8.GetBytes(expected));

    public static string ClientIp(HttpContext context) => context.Connection.RemoteIpAddress?.ToString() ?? "unknown";

    private static void RedirectError(HttpContext context, string redirectUri, string error, string? state, int status = StatusCodes.Status302Found)
    {
        var parameters = new List<KeyValuePair<string, string?>> { new("error", error), new("error_description", Descriptions[error]) };
        if (state is not null)
        {
            parameters.Add(new("state", state));
        }

        Redirect(context, redirectUri, parameters, status);
    }

    private static void Redirect(HttpContext context, string redirectUri, List<KeyValuePair<string, string?>> parameters, int status)
    {
        context.Response.StatusCode = status;
        context.Response.Headers.Location = QueryHelpers.AddQueryString(redirectUri, parameters);
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.Pragma = "no-cache";
    }

    private static Task WriteError(HttpContext context, int status, string error) =>
        WriteJson(context, status, JsonSerializer.Serialize(new Dictionary<string, string> { ["error"] = error, ["error_description"] = Descriptions[error] }));

    private static Task WriteJson(HttpContext context, int status, string json)
    {
        context.Response.StatusCode = status;
        context.Response.ContentType = "application/json";
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.Pragma = "no-cache";
        return context.Response.WriteAsync(json);
    }

    private static Task Status(HttpContext context, int status)
    {
        context.Response.StatusCode = status;
        context.Response.Headers.CacheControl = "no-store";
        return Task.CompletedTask;
    }

    private static Task TooManyRequests(HttpContext context, TimeSpan retryAfter)
    {
        context.Response.Headers.RetryAfter = Math.Max(1, (int)Math.Ceiling(retryAfter.TotalSeconds)).ToString(CultureInfo.InvariantCulture);
        return Status(context, 429);
    }

    /// <summary>
    /// An HTML page with the headers of R18. form-action also allows the client's redirect origin when the page's
    /// form can end in a redirect to it: browsers apply form-action to the redirect that follows a form post.
    /// </summary>
    private static Task WritePage(HttpContext context, int status, string html, string? redirectUri)
    {
        var formAction = redirectUri is null ? "'self'" : $"'self' {RedirectUriRules.Origin(redirectUri)}";
        context.Response.StatusCode = status;
        context.Response.ContentType = "text/html; charset=utf-8";
        context.Response.Headers.ContentSecurityPolicy =
            $"default-src 'none'; style-src 'self'; img-src 'self'; form-action {formAction}; base-uri 'none'; frame-ancestors 'none'";
        context.Response.Headers.XFrameOptions = "DENY";
        context.Response.Headers.XContentTypeOptions = "nosniff";
        context.Response.Headers["Referrer-Policy"] = "same-origin";   // not no-referrer: that makes browsers send "Origin: null" on our form posts
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.Pragma = "no-cache";
        return context.Response.WriteAsync(html);
    }

    // RFC 7636 code_challenge and code_verifier: 43 to 128 unreserved characters.
    [GeneratedRegex("^[A-Za-z0-9\\-._~]{43,128}$")]
    private static partial Regex PkceValue();
}
