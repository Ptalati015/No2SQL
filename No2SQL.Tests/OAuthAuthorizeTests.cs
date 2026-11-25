using System.Net;
using Microsoft.Extensions.DependencyInjection;
using No2SQL.Hosting.OAuth;
using No2SQL.Tests.Infrastructure;

namespace No2SQL.Tests;

/// <summary>
/// The authorization endpoint, owner login and consent (P2-5 threat model R11 to R18; tests 1, 2, 3, 12, 13
/// and the page half of 14).
/// </summary>
public sealed class OAuthAuthorizeTests : IDisposable
{
    private const string Redirect = "https://client.example.test/callback";

    private static CancellationToken Cancel => TestContext.Current.CancellationToken;

    private readonly BuiltinAuthServer _server = new();

    public void Dispose() => _server.Dispose();

    private async Task<(string ClientId, Dictionary<string, string?> Parameters)> ValidRequestAsync(string redirectUri = Redirect, string? name = "Test client")
    {
        var clientId = await _server.RegisterAsync(redirectUri, name);
        return (clientId, BuiltinAuthServer.AuthorizeParameters(clientId, redirectUri, BuiltinAuthServer.NewPkce().Challenge));
    }

    private async Task<string> LoginPageAsync(Dictionary<string, string?> parameters)
    {
        using var response = await _server.AuthorizeAsync(parameters);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.Content.ReadAsStringAsync(Cancel);
    }

    private static void AssertPageHeaders(HttpResponseMessage response)
    {
        var csp = string.Join(";", response.Headers.GetValues("Content-Security-Policy"));
        Assert.Contains("default-src 'none'", csp);
        Assert.Contains("style-src 'self'", csp);
        Assert.Contains("frame-ancestors 'none'", csp);
        Assert.Contains("base-uri 'none'", csp);
        Assert.Contains("form-action 'self'", csp);
        Assert.DoesNotContain("script-src", csp);
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);
    }

    // ---- R11: client and redirect URI first; until both are valid, never a redirect ----

    [Fact]
    public async Task An_unregistered_redirect_URI_gets_an_error_page_with_no_redirect_and_no_echo()
    {
        var (_, parameters) = await ValidRequestAsync();
        parameters["redirect_uri"] = "https://evil.example/steal";

        using var response = await _server.AuthorizeAsync(parameters);
        var body = await response.Content.ReadAsStringAsync(Cancel);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.DoesNotContain("evil.example", body);
        Assert.DoesNotContain("state-123", body);
        Assert.DoesNotContain("<a ", body);
        AssertPageHeaders(response);
    }

    [Theory]
    [InlineData("unknown-client")]
    [InlineData("")]
    public async Task An_unknown_client_gets_an_error_page(string clientId)
    {
        var (_, parameters) = await ValidRequestAsync();
        parameters["client_id"] = clientId;

        using var response = await _server.AuthorizeAsync(parameters);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    [Fact]
    public async Task A_redirect_URI_that_differs_in_any_way_is_not_registered()
    {
        var (_, parameters) = await ValidRequestAsync();
        foreach (var variant in new[] { Redirect + "/", Redirect + "?x=1", "https://CLIENT.example.test/callback/../callback", "http://client.example.test/callback" })
        {
            parameters["redirect_uri"] = variant;
            using var response = await _server.AuthorizeAsync(parameters);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
    }

    [Fact]
    public async Task A_loopback_redirect_may_use_any_port()
    {
        var (_, parameters) = await ValidRequestAsync("http://127.0.0.1:0/callback");
        parameters["redirect_uri"] = "http://127.0.0.1:53111/callback";

        var page = await LoginPageAsync(parameters);

        Assert.Contains("Sign in to No2SQL", page);
    }

    [Fact]
    public async Task A_repeated_client_id_gets_an_error_page()
    {
        var (clientId, parameters) = await ValidRequestAsync();
        using var response = await _server.Client.GetAsync(
            $"/authorize?client_id={clientId}&client_id={clientId}&redirect_uri={Uri.EscapeDataString(Redirect)}", Cancel);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    [Fact]
    public async Task A_query_over_8_KiB_gets_an_error_page()
    {
        var (_, parameters) = await ValidRequestAsync();
        parameters["padding"] = new string('a', 8200);

        using var response = await _server.AuthorizeAsync(parameters);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    // ---- R12: after that, errors go back to the client with fixed descriptions ----

    private async Task AssertRedirectError(Dictionary<string, string?> parameters, string error)
    {
        using var response = await _server.AuthorizeAsync(parameters);
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.StartsWith(Redirect + "?", response.Headers.Location!.ToString());
        Assert.Equal(error, BuiltinAuthServer.FromLocation(response, "error"));
        Assert.Equal(parameters.GetValueOrDefault("state"), BuiltinAuthServer.FromLocation(response, "state"));
        Assert.NotNull(BuiltinAuthServer.FromLocation(response, "error_description"));
        Assert.Null(BuiltinAuthServer.FromLocation(response, "code"));
    }

    [Theory]
    [InlineData("plain")]
    [InlineData(null)]
    [InlineData("s256")]
    public async Task PKCE_must_be_S256(string? method)
    {
        var (_, parameters) = await ValidRequestAsync();
        parameters["code_challenge_method"] = method;
        await AssertRedirectError(parameters, "invalid_request");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("short")]
    [InlineData("has spaces in it and is long enough to pass the length check only")]
    public async Task A_missing_or_malformed_code_challenge_is_refused(string? challenge)
    {
        var (_, parameters) = await ValidRequestAsync();
        parameters["code_challenge"] = challenge;
        await AssertRedirectError(parameters, "invalid_request");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("https://other.example/mcp")]
    [InlineData("https://mcp.example.test/")]
    [InlineData("https://mcp.example.test/mcp/other")]
    [InlineData("https://mcp.example.test/mcp?x=1")]
    [InlineData("http://mcp.example.test/mcp")]
    public async Task The_resource_must_be_this_MCP_endpoint(string? resource)
    {
        var (_, parameters) = await ValidRequestAsync();
        parameters["resource"] = resource;
        await AssertRedirectError(parameters, "invalid_target");
    }

    [Theory]
    [InlineData("https://mcp.example.test/mcp/")]
    [InlineData("https://MCP.example.test/mcp")]
    public async Task The_resource_comparison_ignores_a_trailing_slash_and_host_case(string resource)
    {
        var (_, parameters) = await ValidRequestAsync();
        parameters["resource"] = resource;
        Assert.Contains("Sign in to No2SQL", await LoginPageAsync(parameters));
    }

    [Theory]
    [InlineData("token")]
    [InlineData("code id_token")]
    [InlineData(null)]
    public async Task Only_response_type_code_is_supported(string? responseType)
    {
        var (_, parameters) = await ValidRequestAsync();
        parameters["response_type"] = responseType;
        await AssertRedirectError(parameters, "unsupported_response_type");
    }

    [Theory]
    [InlineData("openid")]
    [InlineData("mcp:tools admin")]
    [InlineData("   ")]
    public async Task Unknown_scopes_are_an_error_not_dropped(string scope)
    {
        var (_, parameters) = await ValidRequestAsync();
        parameters["scope"] = scope;
        await AssertRedirectError(parameters, "invalid_scope");
    }

    [Fact]
    public async Task A_parameter_over_2_KiB_or_repeated_is_refused()
    {
        var (_, parameters) = await ValidRequestAsync();
        parameters["state"] = new string('s', 2100);
        using (var response = await _server.AuthorizeAsync(parameters))
        {
            Assert.Equal("invalid_request", BuiltinAuthServer.FromLocation(response, "error"));
            Assert.Null(BuiltinAuthServer.FromLocation(response, "state"));
        }

        var (clientId, _) = await ValidRequestAsync();
        using var repeated = await _server.Client.GetAsync(
            $"/authorize?client_id={clientId}&redirect_uri={Uri.EscapeDataString(Redirect)}&scope=mcp:tools&scope=offline_access", Cancel);
        Assert.Equal("invalid_request", BuiltinAuthServer.FromLocation(repeated, "error"));
    }

    // ---- R13, R18: the pages ----

    [Fact]
    public async Task The_login_and_consent_pages_name_an_unverified_client_and_the_redirect_host()
    {
        var (_, parameters) = await ValidRequestAsync(name: "<script>alert(1)</script>ChatGPT");
        using var authorize = await _server.AuthorizeAsync(parameters);
        var loginPage = await authorize.Content.ReadAsStringAsync(Cancel);
        AssertPageHeaders(authorize);
        Assert.Contains("Unverified client: <strong>&lt;script&gt;alert(1)&lt;/script&gt;ChatGPT</strong>", loginPage);
        Assert.DoesNotContain("<script>", loginPage);
        Assert.Contains("form-action 'self' https://client.example.test", string.Join(";", authorize.Headers.GetValues("Content-Security-Policy")));

        using var login = await _server.LoginAsync(loginPage, _server.Password);
        var consentPage = await login.Content.ReadAsStringAsync(Cancel);
        AssertPageHeaders(login);
        Assert.Contains("Unverified client: <strong>", consentPage);
        Assert.Contains("No2SQL cannot check who this client is", consentPage);
        Assert.Contains("the authorization is sent to <strong>client.example.test</strong>", consentPage);
        Assert.Contains("read your MongoDB databases through No2SQL until you revoke it", consentPage);
        Assert.Contains("mcp:tools", consentPage);
        Assert.Contains("offline_access", consentPage);
        Assert.Contains("value=\"approve\"", consentPage);
        Assert.Contains("value=\"deny\"", consentPage);
        Assert.DoesNotContain("<script", consentPage);
        Assert.DoesNotContain("state-123", consentPage);
    }

    [Fact]
    public async Task A_loopback_redirect_is_described_as_an_app_on_this_computer()
    {
        var flowClient = await _server.RegisterAsync("http://127.0.0.1:0/cb");
        var parameters = BuiltinAuthServer.AuthorizeParameters(flowClient, "http://127.0.0.1:41000/cb", BuiltinAuthServer.NewPkce().Challenge);
        using var login = await _server.LoginAsync(await LoginPageAsync(parameters), _server.Password);

        Assert.Contains("sent to <strong>an app on your computer</strong>", await login.Content.ReadAsStringAsync(Cancel));
    }

    [Fact]
    public async Task The_error_page_and_the_stylesheet_carry_the_page_headers()
    {
        using var error = await _server.Client.GetAsync("/authorize?client_id=nobody&redirect_uri=https%3A%2F%2Fa.example%2F", Cancel);
        AssertPageHeaders(error);
        Assert.DoesNotContain("form-action 'self' https://a.example", string.Join(";", error.Headers.GetValues("Content-Security-Policy")));

        using var css = await _server.Client.GetAsync(OAuthPages.StylePath, Cancel);
        Assert.Equal("text/css", css.Content.Headers.ContentType?.MediaType);
    }

    // ---- R14: password guessing ----

    [Fact]
    public async Task A_wrong_password_gets_the_login_page_again_and_is_logged_without_the_password()
    {
        var (_, parameters) = await ValidRequestAsync();
        var page = await LoginPageAsync(parameters);

        using var response = await _server.LoginAsync(page, "Wrong-Password-Attempt-1");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.False(response.Headers.Contains("Set-Cookie"));
        Assert.Contains("That password is not correct.", await response.Content.ReadAsStringAsync(Cancel));
        Assert.Contains(_server.Logs.Lines, line => line.Contains("Owner login failed from 203.0.113.10"));
        Assert.DoesNotContain(_server.Logs.Lines, line => line.Contains("Wrong-Password-Attempt-1"));
    }

    [Fact]
    public async Task After_five_failures_the_sixth_attempt_waits_two_seconds_and_the_21st_is_refused_unchecked()
    {
        var (_, parameters) = await ValidRequestAsync();
        var page = await LoginPageAsync(parameters);
        for (var i = 0; i < 5; i++)
        {
            using var wrong = await _server.LoginAsync(page, "wrong-password-" + i);
            Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        }

        // The sixth answer does not arrive until two seconds have passed on the server's clock.
        var sixth = _server.LoginAsync(page, "wrong-password-5");
        await Task.Delay(200, Cancel);
        Assert.False(sixth.IsCompleted);
        _server.Clock.Advance(TimeSpan.FromSeconds(1.9));
        await Task.Delay(100, Cancel);
        Assert.False(sixth.IsCompleted);
        _server.Clock.Advance(TimeSpan.FromSeconds(0.1));
        using (var answered = await sixth.WaitAsync(TimeSpan.FromSeconds(10), Cancel))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, answered.StatusCode);
        }

        // Failures 7 to 20 (each waits longer, capped at 60 s).
        for (var i = 6; i < 20; i++)
        {
            page = await LoginPageAsync(parameters);   // the waits add up to more than a request's ten minutes
            var attempt = _server.LoginAsync(page, "wrong-password-" + i);
            while (!attempt.IsCompleted)
            {
                _server.Clock.Advance(TimeSpan.FromSeconds(1));
                await Task.Delay(5, Cancel);
            }

            using var wrong = await attempt;
            Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        }

        // The 21st is refused without checking, even with the right password.
        page = await LoginPageAsync(parameters);
        using var refused = await _server.LoginAsync(page, _server.Password);
        Assert.Equal((HttpStatusCode)429, refused.StatusCode);
        Assert.False(refused.Headers.Contains("Set-Cookie"));

        // Another address is still served; an hour later this one is too.
        using var other = await _server.LoginAsync(page, _server.Password, ip: "198.51.100.99");
        Assert.Equal(HttpStatusCode.OK, other.StatusCode);
    }

    [Fact]
    public async Task One_hundred_failures_an_hour_from_all_addresses_lock_login_for_everyone()
    {
        var (_, parameters) = await ValidRequestAsync();
        var page = await LoginPageAsync(parameters);
        for (var i = 0; i < 100; i++)
        {
            using var wrong = await _server.LoginAsync(page, "wrong", ip: $"192.0.2.{i / 5}");   // five each: no delay yet
            Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        }

        using var locked = await _server.LoginAsync(page, _server.Password, ip: "198.51.100.200");
        Assert.Equal((HttpStatusCode)429, locked.StatusCode);

        _server.Clock.Advance(TimeSpan.FromHours(1));
        using var open = await _server.LoginAsync(await LoginPageAsync(parameters), _server.Password, ip: "198.51.100.200");
        Assert.Equal(HttpStatusCode.OK, open.StatusCode);
    }

    // ---- R16: the owner session ----

    [Fact]
    public async Task Login_sets_a_new_host_only_strict_secure_session_cookie_each_time()
    {
        var (_, parameters) = await ValidRequestAsync();
        using var first = await _server.LoginAsync(await LoginPageAsync(parameters), _server.Password);
        using var second = await _server.LoginAsync(await LoginPageAsync(parameters), _server.Password);

        var header = first.Headers.GetValues("Set-Cookie").Single();
        Assert.Matches("^__Host-no2sql_owner=[A-Za-z0-9_-]{43}; Path=/; Max-Age=600; Secure; HttpOnly; SameSite=Strict$", header);
        Assert.DoesNotContain("Domain", header);
        Assert.NotEqual(BuiltinAuthServer.SessionCookie(first), BuiltinAuthServer.SessionCookie(second));
    }

    [Fact]
    public async Task A_session_expires_after_ten_minutes()
    {
        var (_, parameters) = await ValidRequestAsync();
        using var login = await _server.LoginAsync(await LoginPageAsync(parameters), _server.Password);
        var consentPage = await login.Content.ReadAsStringAsync(Cancel);

        _server.Clock.Advance(TimeSpan.FromMinutes(10));
        using var late = await _server.ConsentAsync(consentPage, BuiltinAuthServer.SessionCookie(login));

        Assert.Equal(HttpStatusCode.Forbidden, late.StatusCode);
        Assert.Null(late.Headers.Location);
    }

    // ---- R17: consent is POST only, with the session, the anti-forgery token and our Origin ----

    private async Task<(string ConsentPage, string Cookie)> ConsentPageAsync()
    {
        var (_, parameters) = await ValidRequestAsync();
        using var login = await _server.LoginAsync(await LoginPageAsync(parameters), _server.Password);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        return (await login.Content.ReadAsStringAsync(Cancel), BuiltinAuthServer.SessionCookie(login));
    }

    [Fact]
    public async Task Consent_without_the_anti_forgery_token_is_403_and_issues_no_code()
    {
        var (page, cookie) = await ConsentPageAsync();
        using var response = await _server.PostFormAsync(OAuthServerEndpoints.ConsentPath, new()
        {
            ["request"] = BuiltinAuthServer.Hidden(page, "request"),
            ["decision"] = "approve",
        }, cookie);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Null(response.Headers.Location);

        using var approved = await _server.ConsentAsync(page, cookie);   // the request is still answerable with the token
        Assert.Equal(HttpStatusCode.SeeOther, approved.StatusCode);
    }

    [Theory]
    [InlineData("https://evil.example")]
    [InlineData("null")]
    [InlineData("http://mcp.example.test")]
    [InlineData("https://mcp.example.test.evil.example")]
    public async Task Consent_from_another_origin_is_403(string origin)
    {
        var (page, cookie) = await ConsentPageAsync();
        using var response = await _server.PostFormAsync(OAuthServerEndpoints.ConsentPath, new()
        {
            ["request"] = BuiltinAuthServer.Hidden(page, "request"),
            ["csrf"] = BuiltinAuthServer.Hidden(page, "csrf"),
            ["decision"] = "approve",
        }, cookie, origin: origin);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    [Fact]
    public async Task Without_an_Origin_the_Referer_must_be_one_of_our_pages()
    {
        var (page, cookie) = await ConsentPageAsync();
        var fields = new Dictionary<string, string?>
        {
            ["request"] = BuiltinAuthServer.Hidden(page, "request"),
            ["csrf"] = BuiltinAuthServer.Hidden(page, "csrf"),
            ["decision"] = "approve",
        };

        using var noHeaders = await _server.PostFormAsync(OAuthServerEndpoints.ConsentPath, fields, cookie, origin: null);
        Assert.Equal(HttpStatusCode.Forbidden, noHeaders.StatusCode);

        using var foreign = await _server.PostFormAsync(OAuthServerEndpoints.ConsentPath, fields, cookie, origin: null, referer: "https://evil.example/mcp.example.test/");
        Assert.Equal(HttpStatusCode.Forbidden, foreign.StatusCode);

        using var ours = await _server.PostFormAsync(OAuthServerEndpoints.ConsentPath, fields, cookie, origin: null, referer: "https://mcp.example.test/login");
        Assert.Equal(HttpStatusCode.SeeOther, ours.StatusCode);
    }

    [Fact]
    public async Task Consent_needs_the_session_that_logged_in_for_this_request()
    {
        var (page, _) = await ConsentPageAsync();
        var (_, otherCookie) = await ConsentPageAsync();

        using var noCookie = await _server.PostFormAsync(OAuthServerEndpoints.ConsentPath, new()
        {
            ["request"] = BuiltinAuthServer.Hidden(page, "request"),
            ["csrf"] = BuiltinAuthServer.Hidden(page, "csrf"),
            ["decision"] = "approve",
        });
        Assert.Equal(HttpStatusCode.Forbidden, noCookie.StatusCode);

        using var wrongSession = await _server.ConsentAsync(page, otherCookie);
        Assert.Equal(HttpStatusCode.Forbidden, wrongSession.StatusCode);
    }

    [Fact]
    public async Task Login_also_checks_the_Origin_and_its_anti_forgery_token()
    {
        var (_, parameters) = await ValidRequestAsync();
        var page = await LoginPageAsync(parameters);

        using var foreign = await _server.PostFormAsync(OAuthServerEndpoints.LoginPath, new()
        {
            ["request"] = BuiltinAuthServer.Hidden(page, "request"),
            ["csrf"] = BuiltinAuthServer.Hidden(page, "csrf"),
            ["password"] = _server.Password,
        }, origin: "https://evil.example");
        Assert.Equal(HttpStatusCode.Forbidden, foreign.StatusCode);

        using var noToken = await _server.PostFormAsync(OAuthServerEndpoints.LoginPath, new()
        {
            ["request"] = BuiltinAuthServer.Hidden(page, "request"),
            ["password"] = _server.Password,
        });
        Assert.Equal(HttpStatusCode.Forbidden, noToken.StatusCode);
        Assert.False(noToken.Headers.Contains("Set-Cookie"));
    }

    [Fact]
    public async Task Consent_is_never_accepted_by_GET_and_answers_once()
    {
        using var get = await _server.Client.GetAsync(OAuthServerEndpoints.ConsentPath + "?decision=approve", Cancel);
        Assert.Equal(HttpStatusCode.MethodNotAllowed, get.StatusCode);

        var (page, cookie) = await ConsentPageAsync();
        using var first = await _server.ConsentAsync(page, cookie);
        using var second = await _server.ConsentAsync(page, cookie);

        Assert.Equal(HttpStatusCode.SeeOther, first.StatusCode);
        Assert.NotEqual(HttpStatusCode.SeeOther, second.StatusCode);
        Assert.Null(second.Headers.Location);
    }

    [Fact]
    public async Task Approve_redirects_with_a_code_and_the_state_and_deny_with_access_denied()
    {
        var (page, cookie) = await ConsentPageAsync();
        using var approved = await _server.ConsentAsync(page, cookie);
        Assert.Equal(HttpStatusCode.SeeOther, approved.StatusCode);
        Assert.StartsWith(Redirect + "?", approved.Headers.Location!.ToString());
        Assert.Matches("^[A-Za-z0-9_-]{43}$", BuiltinAuthServer.FromLocation(approved, "code")!);
        Assert.Equal("state-123", BuiltinAuthServer.FromLocation(approved, "state"));

        var (page2, cookie2) = await ConsentPageAsync();
        using var denied = await _server.ConsentAsync(page2, cookie2, "deny");
        Assert.Equal("access_denied", BuiltinAuthServer.FromLocation(denied, "error"));
        Assert.Equal("state-123", BuiltinAuthServer.FromLocation(denied, "state"));
        Assert.Null(BuiltinAuthServer.FromLocation(denied, "code"));
    }

    [Fact]
    public async Task Approving_a_registered_client_protects_it_from_eviction()
    {
        var flow = await _server.AuthorizeFullyAsync();

        Assert.NotNull(_server.Services.GetRequiredService<ClientStore>().Find(flow.ClientId)!.ApprovedAt);
    }

    [Fact]
    public async Task A_registered_client_is_asked_for_consent_every_time()
    {
        var clientId = await _server.RegisterAsync();
        await _server.AuthorizeFullyAsync(clientId);

        var parameters = BuiltinAuthServer.AuthorizeParameters(clientId, Redirect, BuiltinAuthServer.NewPkce().Challenge);
        using var login = await _server.LoginAsync(await LoginPageAsync(parameters), _server.Password);

        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        Assert.Contains("Allow access to your databases?", await login.Content.ReadAsStringAsync(Cancel));
    }
}
