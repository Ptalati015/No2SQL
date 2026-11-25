using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.Tokens;
using No2SQL.Hosting;
using No2SQL.Hosting.OAuth;

namespace No2SQL.Tests.Infrastructure;

/// <summary>
/// HTTP mode with the built-in authorization server (NO2SQL_OAUTH_BUILTIN=true) on an in-memory server, with a
/// fresh data directory, a movable clock, captured logs and helpers for each step of the OAuth flow.
/// Requests carry <c>X-Test-Client-IP</c> to choose the client address (default 203.0.113.10).
/// </summary>
internal sealed partial class BuiltinAuthServer : IDisposable
{
    public const string PublicUrl = "https://mcp.example.test";
    public const string McpUrl = PublicUrl + "/mcp";
    public const string ClientIpHeader = "X-Test-Client-IP";
    public const string DefaultClientIp = "203.0.113.10";

    private readonly No2SqlHttpApp _app;

    /// <param name="configureServices">Extra test services, for example metadata-document stubs.</param>
    /// <param name="configurePipeline">Extra test endpoints in front of the application.</param>
    /// <param name="ownerPassword">NO2SQL_OWNER_PASSWORD; null means a generated one.</param>
    /// <param name="staticToken">NO2SQL_HTTP_TOKEN as well, when set.</param>
    /// <param name="mongoConnectionString">What NO2SQL_MONGO would hold.</param>
    public BuiltinAuthServer(
        Action<IServiceCollection>? configureServices = null,
        Action<IApplicationBuilder>? configurePipeline = null,
        string? ownerPassword = "",
        string? staticToken = null,
        TimeSpan? accessTokenLifetime = null,
        string? mongoConnectionString = null)
    {
        DataDirectory = Path.Combine(Path.GetTempPath(), "no2sql-oauth-" + Guid.NewGuid().ToString("N"));
        Password = ownerPassword == "" ? "pw-" + Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(18)) : ownerPassword;
        Options = new HttpAuthOptions
        {
            Builtin = true,
            PublicUrl = new Uri(PublicUrl),
            DataDirectory = DataDirectory,
            OwnerPassword = Password,
            StaticToken = staticToken,
            AccessTokenLifetime = accessTokenLifetime ?? TimeSpan.FromMinutes(60),
        };

        _app = new No2SqlHttpApp(
            services =>
            {
                services.AddSingleton<TimeProvider>(Clock);
                services.AddLogging(logging => logging.AddProvider(Logs));
                services.AddSingleton<IStartupFilter>(new TestPipeline(configurePipeline));
                configureServices?.Invoke(services);
            },
            mongoConnectionString,
            Options);
        Client = _app.CreateClient();
        _ = Directory;   // creates the data directory and the first key, as start-up does in the real process
    }

    public FakeTimeProvider Clock { get; } = new(new DateTimeOffset(2026, 11, 25, 12, 0, 0, TimeSpan.Zero));

    public CapturedLogs Logs { get; } = new();

    public HttpClient Client { get; }

    public HttpAuthOptions Options { get; }

    public string DataDirectory { get; }

    /// <summary>The owner password, or null when the server generated one.</summary>
    public string? Password { get; }

    public IServiceProvider Services => _app.Services;

    public OAuthDataDirectory Directory => Services.GetRequiredService<OAuthDataDirectory>();

    public void Dispose()
    {
        Client.Dispose();
        _app.Dispose();
        try
        {
            System.IO.Directory.Delete(DataDirectory, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    private static CancellationToken Cancel => TestContext.Current.CancellationToken;

    // ---- Registration ----

    public async Task<HttpResponseMessage> RegisterRawAsync(string json, string ip = DefaultClientIp, string contentType = "application/json")
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, OAuthServerEndpoints.RegisterPath)
        {
            Content = new StringContent(json, Encoding.UTF8),
        };
        request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(contentType);
        request.Headers.Add(ClientIpHeader, ip);
        return await Client.SendAsync(request, Cancel);
    }

    /// <summary>Registers a client and returns its client_id.</summary>
    public async Task<string> RegisterAsync(string redirectUri = "https://client.example.test/callback", string? name = "Test client", string ip = DefaultClientIp)
    {
        var body = new JsonObject { ["redirect_uris"] = new JsonArray(redirectUri), ["token_endpoint_auth_method"] = "none" };
        if (name is not null)
        {
            body["client_name"] = name;
        }

        using var response = await RegisterRawAsync(body.ToJsonString(), ip);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return (string)JsonNode.Parse(await response.Content.ReadAsStringAsync(Cancel))!["client_id"]!;
    }

    // ---- Authorization ----

    public static (string Verifier, string Challenge) NewPkce()
    {
        var verifier = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        return (verifier, Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))));
    }

    /// <summary>The authorize query for a valid request; each named argument changes or (with null) drops one parameter.</summary>
    public static Dictionary<string, string?> AuthorizeParameters(string clientId, string redirectUri, string challenge) => new()
    {
        ["response_type"] = "code",
        ["client_id"] = clientId,
        ["redirect_uri"] = redirectUri,
        ["code_challenge"] = challenge,
        ["code_challenge_method"] = "S256",
        ["resource"] = McpUrl,
        ["scope"] = "mcp:tools offline_access",
        ["state"] = "state-123",
    };

    public async Task<HttpResponseMessage> AuthorizeAsync(Dictionary<string, string?> parameters, string? cookie = null, string ip = DefaultClientIp)
    {
        var query = string.Join("&", parameters.Where(p => p.Value is not null).Select(p => $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value!)}"));
        using var request = new HttpRequestMessage(HttpMethod.Get, OAuthServerEndpoints.AuthorizePath + "?" + query);
        request.Headers.Add(ClientIpHeader, ip);
        if (cookie is not null)
        {
            request.Headers.Add("Cookie", cookie);
        }

        return await Client.SendAsync(request, Cancel);
    }

    /// <summary>A hidden form field of a login or consent page.</summary>
    public static string Hidden(string html, string name)
    {
        var match = Regex.Match(html, $"name=\"{Regex.Escape(name)}\" value=\"([^\"]*)\"");
        Assert.True(match.Success, $"no hidden field {name}");
        return WebUtility.HtmlDecode(match.Groups[1].Value);
    }

    public async Task<HttpResponseMessage> PostFormAsync(string path, Dictionary<string, string?> fields, string? cookie = null, string? origin = PublicUrl, string? referer = null, string ip = DefaultClientIp)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new FormUrlEncodedContent(fields.Where(f => f.Value is not null).Select(f => new KeyValuePair<string, string>(f.Key, f.Value!))),
        };
        request.Headers.Add(ClientIpHeader, ip);
        if (origin is not null)
        {
            request.Headers.Add("Origin", origin);
        }

        if (referer is not null)
        {
            request.Headers.Referrer = new Uri(referer);
        }

        if (cookie is not null)
        {
            request.Headers.Add("Cookie", cookie);
        }

        return await Client.SendAsync(request, Cancel);
    }

    /// <summary>Submits the login page's form with a password.</summary>
    public async Task<HttpResponseMessage> LoginAsync(string loginPage, string? password, string ip = DefaultClientIp) =>
        await PostFormAsync(OAuthServerEndpoints.LoginPath, new()
        {
            ["request"] = Hidden(loginPage, "request"),
            ["csrf"] = Hidden(loginPage, "csrf"),
            ["password"] = password,
        }, ip: ip);

    /// <summary>The session cookie (name=value) a successful login set.</summary>
    public static string SessionCookie(HttpResponseMessage login)
    {
        var header = login.Headers.GetValues("Set-Cookie").Single(h => h.StartsWith(OAuthServerEndpoints.SessionCookie + "=", StringComparison.Ordinal));
        return header.Split(';')[0];
    }

    public async Task<HttpResponseMessage> ConsentAsync(string consentPage, string cookie, string decision = "approve") =>
        await PostFormAsync(OAuthServerEndpoints.ConsentPath, new()
        {
            ["request"] = Hidden(consentPage, "request"),
            ["csrf"] = Hidden(consentPage, "csrf"),
            ["decision"] = decision,
        }, cookie);

    /// <summary>A query parameter of a redirect's Location.</summary>
    public static string? FromLocation(HttpResponseMessage redirect, string name)
    {
        var location = redirect.Headers.Location!;
        var parameters = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(location.Query);
        return parameters.TryGetValue(name, out var value) ? value.ToString() : null;
    }

    /// <summary>Register (unless a client is given), authorize, log in, approve: returns the authorization code and its verifier.</summary>
    public async Task<FlowResult> AuthorizeFullyAsync(string? clientId = null, string redirectUri = "https://client.example.test/callback", string scope = "mcp:tools offline_access")
    {
        clientId ??= await RegisterAsync(redirectUri);
        var (verifier, challenge) = NewPkce();
        var parameters = AuthorizeParameters(clientId, redirectUri, challenge);
        parameters["scope"] = scope;

        using var authorize = await AuthorizeAsync(parameters);
        Assert.Equal(HttpStatusCode.OK, authorize.StatusCode);
        var loginPage = await authorize.Content.ReadAsStringAsync(Cancel);

        using var login = await LoginAsync(loginPage, Password);
        var cookie = SessionCookie(login);
        HttpResponseMessage approved;
        if (login.StatusCode == HttpStatusCode.SeeOther)
        {
            approved = login;   // a remembered metadata-document approval skips the consent page
        }
        else
        {
            Assert.Equal(HttpStatusCode.OK, login.StatusCode);
            approved = await ConsentAsync(await login.Content.ReadAsStringAsync(Cancel), cookie);
        }

        Assert.Equal(HttpStatusCode.SeeOther, approved.StatusCode);
        var code = FromLocation(approved, "code");
        Assert.NotNull(code);
        return new FlowResult(clientId, redirectUri, code, verifier, cookie);
    }

    // ---- Tokens ----

    public async Task<HttpResponseMessage> TokenRawAsync(Dictionary<string, string?> fields, string ip = DefaultClientIp)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, OAuthServerEndpoints.TokenPath)
        {
            Content = new FormUrlEncodedContent(fields.Where(f => f.Value is not null).Select(f => new KeyValuePair<string, string>(f.Key, f.Value!))),
        };
        request.Headers.Add(ClientIpHeader, ip);
        return await Client.SendAsync(request, Cancel);
    }

    public async Task<(HttpStatusCode Status, JsonNode? Body)> ExchangeAsync(FlowResult flow, string? verifier = null, string? clientId = null, string? redirectUri = null)
    {
        using var response = await TokenRawAsync(new()
        {
            ["grant_type"] = "authorization_code",
            ["code"] = flow.Code,
            ["code_verifier"] = verifier ?? flow.Verifier,
            ["client_id"] = clientId ?? flow.ClientId,
            ["redirect_uri"] = redirectUri ?? flow.RedirectUri,
            ["resource"] = McpUrl,
        });
        return (response.StatusCode, JsonNode.Parse(await response.Content.ReadAsStringAsync(Cancel)));
    }

    public async Task<(HttpStatusCode Status, JsonNode? Body)> RefreshAsync(string refreshToken, string clientId, string? scope = null)
    {
        using var response = await TokenRawAsync(new()
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken,
            ["client_id"] = clientId,
            ["scope"] = scope,
        });
        return (response.StatusCode, JsonNode.Parse(await response.Content.ReadAsStringAsync(Cancel)));
    }

    /// <summary>The kid of the active signing key in signing-keys.json.</summary>
    public string ActiveKid() =>
        (string)JsonNode.Parse(File.ReadAllText(Path.Combine(DataDirectory, OAuthDataDirectory.KeysFile)))!["keys"]!.AsArray()
            .Single(k => (string?)k!["status"] == "active")!["kid"]!;

    /// <summary>Authorize and exchange the code: a signed-in client with its first tokens.</summary>
    public async Task<SignedIn> SignInAsync(string? clientId = null, string scope = "mcp:tools offline_access")
    {
        var flow = await AuthorizeFullyAsync(clientId, scope: scope);
        var (status, body) = await ExchangeAsync(flow);
        Assert.Equal(HttpStatusCode.OK, status);
        return new SignedIn(flow, (string)body!["access_token"]!, (string)body["refresh_token"]!);
    }

    /// <summary>The HTTP status /mcp gives a bearer token.</summary>
    public async Task<HttpStatusCode> McpStatusAsync(string accessToken)
    {
        using var response = await CallMcpAsync(accessToken);
        return response.StatusCode;
    }

    /// <summary>Calls a tool on /mcp with a bearer token and returns the HTTP status.</summary>
    public async Task<HttpResponseMessage> CallMcpAsync(string accessToken) =>
        (await Client.RpcAsync("tools/call", new JsonObject { ["name"] = "test_connectivity", ["arguments"] = new JsonObject() },
            request => request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken), Cancel)).Http;

    /// <summary>Signs a token with the active key read from signing-keys.json (R22), with exactly this header and payload.</summary>
    public string SignWithActiveKey(JsonObject header, JsonObject payload) => SignWithKey(header, payload, ActiveKid());

    /// <summary>Signs a token with the private key of this kid in signing-keys.json.</summary>
    public string SignWithKey(JsonObject header, JsonObject payload, string kid)
    {
        var keys = JsonNode.Parse(File.ReadAllText(Path.Combine(DataDirectory, OAuthDataDirectory.KeysFile)))!["keys"]!.AsArray();
        var active = keys.Single(k => (string?)k!["kid"] == kid)!;
        using var ecdsa = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = Base64UrlEncoder.DecodeBytes((string)active["d"]!),
            Q = new ECPoint { X = Base64UrlEncoder.DecodeBytes((string)active["x"]!), Y = Base64UrlEncoder.DecodeBytes((string)active["y"]!) },
        });
        header["kid"] ??= (string)active["kid"]!;
        var input = Base64UrlEncoder.Encode(header.ToJsonString()) + "." + Base64UrlEncoder.Encode(payload.ToJsonString());
        return input + "." + Base64UrlEncoder.Encode(ecdsa.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256));
    }

    /// <summary>A payload the resource server accepts, issued now by the built-in server.</summary>
    public JsonObject GoodPayload()
    {
        var now = Clock.GetUtcNow().ToUnixTimeSeconds();
        return new JsonObject
        {
            ["iss"] = PublicUrl,
            ["sub"] = "owner",
            ["aud"] = McpUrl,
            ["client_id"] = "test-client",
            ["scope"] = "mcp:tools",
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["iat"] = now,
            ["exp"] = now + 600,
        };
    }

    /// <summary>The JSON header and payload of a JWT, unverified.</summary>
    public static (JsonNode Header, JsonNode Payload) Decode(string jwt)
    {
        var parts = jwt.Split('.');
        return (JsonNode.Parse(Base64UrlEncoder.Decode(parts[0]))!, JsonNode.Parse(Base64UrlEncoder.Decode(parts[1]))!);
    }

    /// <summary>Runs a 'No2SQL oauth' command against this server's data directory, as the owner would from a shell.</summary>
    public (int ExitCode, string Output, string Error) Cli(params string[] args)
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var code = OAuthCli.Run(args, name => name == HttpAuthOptions.DataDirectoryVariable ? DataDirectory : null, Clock, output, error);
        return (code, output.ToString(), error.ToString());
    }

    // Sets the client address from X-Test-Client-IP, then runs any extra test endpoints, then the application.
    private sealed class TestPipeline(Action<IApplicationBuilder>? configure) : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use((context, nextMiddleware) =>
            {
                context.Connection.RemoteIpAddress = IPAddress.Parse(
                    context.Request.Headers.TryGetValue(ClientIpHeader, out var ip) && ip.Count == 1 ? ip[0]! : DefaultClientIp);
                return nextMiddleware(context);
            });
            configure?.Invoke(app);
            next(app);
        };
    }
}

/// <summary>An authorization code obtained through the whole flow.</summary>
internal sealed record FlowResult(string ClientId, string RedirectUri, string Code, string Verifier, string SessionCookie);

/// <summary>A client after the whole flow, with the tokens of its code exchange.</summary>
internal sealed record SignedIn(FlowResult Flow, string AccessToken, string RefreshToken)
{
    public string ClientId => Flow.ClientId;
}
