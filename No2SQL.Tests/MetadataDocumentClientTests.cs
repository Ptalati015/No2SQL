using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using No2SQL.Hosting.OAuth;
using No2SQL.Tests.Infrastructure;

namespace No2SQL.Tests;

/// <summary>
/// Client ID Metadata Document clients (P2-5 threat model R8 to R10, R13 and R32; tests 8 and 9). The fetch
/// is driven through /authorize with the DNS resolver, the address policy or the HTTP handler replaced in
/// the test host. None of the three can be replaced by configuration.
/// </summary>
public sealed class MetadataDocumentClientTests
{
    private const string ClientId = "https://client.example.com/oauth/metadata.json";
    private const string Redirect = "https://client.example.com/callback";

    private static CancellationToken Cancel => TestContext.Current.CancellationToken;

    private static string Document(string clientId = ClientId, string? authMethod = "none", params string[] redirectUris)
    {
        var document = new JsonObject
        {
            ["client_id"] = clientId,
            ["client_name"] = "Example client",
            ["redirect_uris"] = new JsonArray([.. (redirectUris.Length == 0 ? [Redirect] : redirectUris).Select(u => (JsonNode)u)]),
        };
        if (authMethod is not null)
        {
            document["token_endpoint_auth_method"] = authMethod;
        }

        return document.ToJsonString();
    }

    private static HttpResponseMessage Json(string body, string contentType = "application/json") => new(HttpStatusCode.OK)
    {
        Content = new StringContent(body, Encoding.UTF8, MediaTypeHeaderValue.Parse(contentType)),
    };

    // A server whose metadata-document fetches are answered by the stub instead of the network.
    private static BuiltinAuthServer ServerWith(StubHandler handler, Action<IServiceCollection>? more = null) => new(services =>
    {
        services.AddSingleton<CimdHandlerFactory>(_ => handler);
        more?.Invoke(services);
    });

    // A server with the production handler and connect callback, and a resolver that answers without DNS.
    private static BuiltinAuthServer ServerWith(StubResolver resolver, ICimdAddressPolicy? policy = null) => new(services =>
    {
        services.AddSingleton<IHostResolver>(resolver);
        if (policy is not null)
        {
            services.AddSingleton(policy);
        }
    });

    private static async Task<HttpResponseMessage> AuthorizeAsync(BuiltinAuthServer server, string clientId = ClientId, string redirectUri = Redirect, string? cookie = null) =>
        await server.AuthorizeAsync(BuiltinAuthServer.AuthorizeParameters(clientId, redirectUri, BuiltinAuthServer.NewPkce().Challenge), cookie);

    private static async Task AssertRefusedAsync(BuiltinAuthServer server, string logged, string clientId = ClientId)
    {
        using var response = await AuthorizeAsync(server, clientId);
        var body = await response.Content.ReadAsStringAsync(Cancel);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.Contains("This application is not registered with this No2SQL server.", body);
        Assert.DoesNotContain("client.example.com", body);
        Assert.Contains(server.Logs.Lines, line => line.Contains(logged));
    }

    // ---- R8: which URLs are fetched at all (the black-box half of test 8) ----

    [Theory]
    [InlineData("http://client.example.com/oauth/metadata.json")]
    [InlineData("https://127.0.0.1/oauth/metadata.json")]
    [InlineData("https://10.0.0.1/oauth/metadata.json")]
    [InlineData("https://169.254.169.254/latest/meta-data/")]
    [InlineData("https://[::1]/oauth/metadata.json")]
    [InlineData("https://[fd00::1]/oauth/metadata.json")]
    [InlineData("https://2130706433/oauth/metadata.json")]
    [InlineData("https://0x7f.0.0.1/oauth/metadata.json")]
    [InlineData("https://127.1/oauth/metadata.json")]
    [InlineData("https://localhost/oauth/metadata.json")]
    [InlineData("https://LOCALHOST./oauth/metadata.json")]
    [InlineData("https://app.localhost/oauth/metadata.json")]
    [InlineData("https://intranet/oauth/metadata.json")]
    [InlineData("https://printer.local/oauth/metadata.json")]
    [InlineData("https://vault.internal/oauth/metadata.json")]
    [InlineData("https://router.home.arpa/oauth/metadata.json")]
    [InlineData("https://client.example.com:8443/oauth/metadata.json")]
    [InlineData("https://user:pw@client.example.com/oauth/metadata.json")]
    [InlineData("https://client.example.com/oauth/metadata.json#fragment")]
    [InlineData("https://client.example.com/")]
    [InlineData("https://client.example.com")]
    [InlineData("https://client.example.com/a b")]
    [InlineData("https://client.example.com/a\\b")]
    public async Task A_client_id_that_is_not_a_public_https_URL_with_a_path_is_refused_without_any_lookup_or_fetch(string clientId)
    {
        var resolver = new StubResolver(_ => [IPAddress.Parse("93.184.216.34")]);
        var handler = new StubHandler(_ => Json(Document(clientId)));
        using var server = ServerWith(handler, services => services.AddSingleton<IHostResolver>(resolver));

        using var response = await AuthorizeAsync(server, clientId);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.Equal(0, handler.Calls);
        Assert.Empty(resolver.Hosts);
    }

    [Fact]
    public void The_URL_rules_accept_an_ordinary_metadata_document_URL()
    {
        Assert.Null(MetadataDocumentClients.CheckUrl(ClientId));
        Assert.Null(MetadataDocumentClients.CheckUrl("https://client.example.com:443/oauth/metadata.json?v=2"));
        Assert.NotNull(MetadataDocumentClients.CheckUrl("https://client.example.com/" + new string('a', 2048)));
    }

    // ---- R8: the address check in the connect callback (the stub-resolver half of test 8) ----

    [Theory]
    [InlineData("169.254.169.254")]
    [InlineData("127.0.0.1")]
    [InlineData("10.1.2.3")]
    [InlineData("192.168.1.10")]
    [InlineData("::1")]
    [InlineData("fd00::10")]
    [InlineData("::ffff:169.254.169.254")]
    [InlineData("93.184.216.34,10.0.0.5")]
    [InlineData("10.0.0.5,93.184.216.34")]
    [InlineData("")]
    public async Task A_host_that_resolves_to_any_address_that_is_not_public_is_refused_before_a_connection_is_made(string addresses)
    {
        var resolver = new StubResolver(_ => [.. addresses.Split(',', StringSplitOptions.RemoveEmptyEntries).Select(IPAddress.Parse)]);
        using var server = ServerWith(resolver);
        var watch = Stopwatch.StartNew();

        await AssertRefusedAsync(server, "Client metadata document from client.example.com refused: the host resolves to an address that is not public.");

        Assert.Equal(new[] { "client.example.com" }, resolver.Hosts);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(6), $"took {watch.Elapsed}");
    }

    [Fact]
    public async Task The_connection_goes_to_the_address_that_was_checked()
    {
        // The policy is replaced to allow loopback, where nothing listens on 443: the callback resolved the
        // name once, asked the policy about that address and tried exactly that address.
        var policy = new RecordingPolicy();
        var resolver = new StubResolver(_ => [IPAddress.Loopback]);
        using var server = ServerWith(resolver, policy);

        await AssertRefusedAsync(server, "Client metadata document from client.example.com refused: the fetch failed (");

        Assert.Equal(new[] { "client.example.com" }, resolver.Hosts);
        Assert.Equal(new[] { IPAddress.Loopback }, policy.Asked);
    }

    [Fact]
    public void The_production_handler_uses_no_proxy_follows_no_redirect_and_has_a_three_second_connect_timeout()
    {
        using var server = new BuiltinAuthServer();
        var clients = server.Services.GetRequiredService<MetadataDocumentClients>();

        using var handler = Assert.IsType<SocketsHttpHandler>(MetadataDocumentClients.CreateHandler(clients));

        Assert.False(handler.UseProxy);
        Assert.False(handler.AllowAutoRedirect);
        Assert.False(handler.UseCookies);
        Assert.Equal(DecompressionMethods.None, handler.AutomaticDecompression);
        Assert.Equal(TimeSpan.FromSeconds(3), handler.ConnectTimeout);
        Assert.NotNull(handler.ConnectCallback);
        Assert.Null(handler.Credentials);
    }

    [Fact]
    public void Nothing_but_the_test_host_replaces_the_resolver_the_address_policy_or_the_handler()
    {
        using var server = new BuiltinAuthServer();

        Assert.IsType<SystemHostResolver>(server.Services.GetRequiredService<IHostResolver>());
        Assert.IsType<PublicAddressPolicy>(server.Services.GetRequiredService<ICimdAddressPolicy>());
        Assert.Equal(nameof(MetadataDocumentClients.CreateHandler), server.Services.GetRequiredService<CimdHandlerFactory>().Method.Name);
    }

    [Theory]
    [InlineData("0.0.0.0")]
    [InlineData("0.1.2.3")]
    [InlineData("10.0.0.1")]
    [InlineData("10.255.255.255")]
    [InlineData("100.64.0.1")]
    [InlineData("100.127.255.255")]
    [InlineData("127.0.0.1")]
    [InlineData("127.255.255.254")]
    [InlineData("169.254.169.254")]
    [InlineData("169.254.0.1")]
    [InlineData("172.16.0.1")]
    [InlineData("172.31.255.255")]
    [InlineData("192.0.0.1")]
    [InlineData("192.0.2.1")]
    [InlineData("192.88.99.1")]
    [InlineData("192.168.0.1")]
    [InlineData("192.168.255.255")]
    [InlineData("198.18.0.1")]
    [InlineData("198.19.255.255")]
    [InlineData("198.51.100.1")]
    [InlineData("203.0.113.1")]
    [InlineData("224.0.0.1")]
    [InlineData("239.255.255.250")]
    [InlineData("240.0.0.1")]
    [InlineData("255.255.255.255")]
    [InlineData("::")]
    [InlineData("::1")]
    [InlineData("::10.0.0.1")]
    [InlineData("::ffff:10.0.0.1")]
    [InlineData("::ffff:127.0.0.1")]
    [InlineData("::ffff:169.254.169.254")]
    [InlineData("64:ff9b::a00:1")]
    [InlineData("64:ff9b::808:808")]
    [InlineData("100::1")]
    [InlineData("2001::1")]
    [InlineData("2001:2::1")]
    [InlineData("2001:10::1")]
    [InlineData("2001:db8::1")]
    [InlineData("2002:a00:1::1")]
    [InlineData("2002:7f00:1::1")]
    [InlineData("2002:c0a8:101::1")]
    [InlineData("3fff::1")]
    [InlineData("4000::1")]
    [InlineData("fc00::1")]
    [InlineData("fd12:3456:789a::1")]
    [InlineData("fe80::1")]
    [InlineData("fec0::1")]
    [InlineData("ff02::1")]
    public void The_address_policy_refuses_every_address_that_is_not_public(string address) =>
        Assert.False(new PublicAddressPolicy().IsAllowed(IPAddress.Parse(address)));

    [Theory]
    [InlineData("1.1.1.1")]
    [InlineData("8.8.8.8")]
    [InlineData("9.255.255.255")]
    [InlineData("11.0.0.1")]
    [InlineData("100.63.255.255")]
    [InlineData("100.128.0.1")]
    [InlineData("169.253.255.255")]
    [InlineData("172.15.255.255")]
    [InlineData("172.32.0.1")]
    [InlineData("192.0.1.1")]
    [InlineData("192.167.255.255")]
    [InlineData("198.17.255.255")]
    [InlineData("198.20.0.1")]
    [InlineData("223.255.255.255")]
    [InlineData("::ffff:8.8.8.8")]
    [InlineData("2001:4860:4860::8888")]
    [InlineData("2002:808:808::1")]
    [InlineData("2606:4700:4700::1111")]
    [InlineData("2a00:1450:4001::1")]
    public void The_address_policy_allows_public_addresses(string address) =>
        Assert.True(new PublicAddressPolicy().IsAllowed(IPAddress.Parse(address)));

    // ---- R9: what a fetch may answer (the stub-handler half of test 8) ----

    [Fact]
    public async Task A_redirect_is_not_followed()
    {
        var handler = new StubHandler(_ =>
        {
            var redirect = new HttpResponseMessage(HttpStatusCode.Found);
            redirect.Headers.Location = new Uri("https://169.254.169.254/latest/meta-data/");
            return redirect;
        });
        using var server = ServerWith(handler);

        await AssertRefusedAsync(server, "Client metadata document from client.example.com refused: HTTP 302.");

        Assert.Equal(1, handler.Calls);
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.NoContent)]
    [InlineData(HttpStatusCode.MovedPermanently)]
    [InlineData(HttpStatusCode.TemporaryRedirect)]
    public async Task Anything_but_200_is_refused_and_not_retried(HttpStatusCode status)
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(status) { Content = new StringContent(Document(), Encoding.UTF8, "application/json") });
        using var server = ServerWith(handler);

        await AssertRefusedAsync(server, $"refused: HTTP {(int)status}.");

        Assert.Equal(1, handler.Calls);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task A_100_KiB_document_is_refused_with_or_without_a_Content_Length(bool withContentLength)
    {
        var padded = Encoding.UTF8.GetBytes(Document() + new string(' ', 100 * 1024));
        var handler = new StubHandler(_ =>
        {
            HttpContent content = withContentLength ? new ByteArrayContent(padded) : new StreamContent(new UnseekableStream(padded));
            content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = content };
        });
        using var server = ServerWith(handler);

        await AssertRefusedAsync(server, "refused: the document is larger than 64 KiB.");
    }

    [Theory]
    [InlineData(64 * 1024, true)]
    [InlineData(64 * 1024 + 1, false)]
    public async Task The_document_limit_is_exactly_64_KiB(int size, bool accepted)
    {
        var document = Document();
        var padded = document + new string(' ', size - Encoding.UTF8.GetByteCount(document));
        using var server = ServerWith(new StubHandler(_ => Json(padded)));

        using var response = await AuthorizeAsync(server);

        Assert.Equal(accepted ? HttpStatusCode.OK : HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Theory]
    [InlineData("text/html")]
    [InlineData("text/plain")]
    [InlineData("application/octet-stream")]
    [InlineData("application/jwt")]
    public async Task A_document_that_is_not_application_json_is_refused(string contentType)
    {
        using var server = ServerWith(new StubHandler(_ => Json(Document(), contentType)));

        await AssertRefusedAsync(server, "refused: the response is not application/json.");
    }

    [Fact]
    public async Task A_document_without_a_content_type_is_refused()
    {
        using var server = ServerWith(new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(Encoding.UTF8.GetBytes(Document())) }));

        await AssertRefusedAsync(server, "refused: the response is not application/json.");
    }

    [Fact]
    public async Task A_server_that_stalls_is_given_up_on_after_five_seconds_on_the_servers_clock()
    {
        var handler = new StubHandler(async (_, cancellation) =>
        {
            await Task.Delay(Timeout.Infinite, cancellation);
            return Json(Document());
        });
        using var server = ServerWith(handler);

        var pending = AuthorizeAsync(server);
        await WaitUntilAsync(() => handler.Calls == 1);
        server.Clock.Advance(TimeSpan.FromSeconds(4.9));
        await Task.Delay(100, Cancel);
        Assert.False(pending.IsCompleted);

        server.Clock.Advance(TimeSpan.FromSeconds(0.1));
        using var response = await pending.WaitAsync(TimeSpan.FromSeconds(10), Cancel);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains(server.Logs.Lines, line => line.Contains("refused: no complete answer within 5 seconds."));
    }

    [Fact]
    public async Task A_body_that_stalls_after_the_headers_is_given_up_on_as_well()
    {
        var handler = new StubHandler(_ =>
        {
            var content = new StreamContent(new StallingStream());
            content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = content };
        });
        using var server = ServerWith(handler);

        var pending = AuthorizeAsync(server);
        await WaitUntilAsync(() => handler.Calls == 1);
        await Task.Delay(100, Cancel);
        server.Clock.Advance(TimeSpan.FromSeconds(5));
        using var response = await pending.WaitAsync(TimeSpan.FromSeconds(10), Cancel);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains(server.Logs.Lines, line => line.Contains("refused: no complete answer within 5 seconds."));
    }

    [Fact]
    public async Task With_the_real_clock_a_server_that_stalls_ten_seconds_is_answered_within_six()
    {
        var handler = new StubHandler(async (_, cancellation) =>
        {
            await Task.Delay(TimeSpan.FromSeconds(10), cancellation);
            return Json(Document());
        });
        using var server = ServerWith(handler, services => services.AddSingleton(TimeProvider.System));
        var watch = Stopwatch.StartNew();

        using var response = await AuthorizeAsync(server);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.InRange(watch.Elapsed, TimeSpan.FromSeconds(4.5), TimeSpan.FromSeconds(6));
    }

    [Fact]
    public async Task A_good_document_is_fetched_once_an_hour_and_a_failure_once_in_five_minutes()
    {
        var fail = false;
        var handler = new StubHandler(_ => fail ? new HttpResponseMessage(HttpStatusCode.ServiceUnavailable) : Json(Document()));
        using var server = ServerWith(handler);

        for (var i = 0; i < 3; i++)
        {
            using var response = await AuthorizeAsync(server);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        Assert.Equal(1, handler.Calls);
        server.Clock.Advance(TimeSpan.FromMinutes(59));
        (await AuthorizeAsync(server)).Dispose();
        Assert.Equal(1, handler.Calls);

        // After the hour it is fetched again; this time the fetch fails, and that is remembered for five minutes.
        fail = true;
        server.Clock.Advance(TimeSpan.FromMinutes(1));
        using var failed = await AuthorizeAsync(server);
        Assert.Equal(HttpStatusCode.BadRequest, failed.StatusCode);
        Assert.Equal(2, handler.Calls);

        fail = false;
        server.Clock.Advance(TimeSpan.FromMinutes(4));
        using var stillFailed = await AuthorizeAsync(server);
        Assert.Equal(HttpStatusCode.BadRequest, stillFailed.StatusCode);
        Assert.Equal(2, handler.Calls);

        server.Clock.Advance(TimeSpan.FromMinutes(1));
        using var recovered = await AuthorizeAsync(server);
        Assert.Equal(HttpStatusCode.OK, recovered.StatusCode);
        Assert.Equal(3, handler.Calls);
    }

    [Fact]
    public async Task At_most_ten_documents_are_fetched_in_a_minute_and_the_eleventh_is_not_held_against_its_client()
    {
        var handler = new StubHandler(request => Json(Document(request.RequestUri!.AbsoluteUri, "none", $"https://{request.RequestUri.Host}/callback")));
        using var server = ServerWith(handler);

        for (var i = 0; i < 10; i++)
        {
            using var response = await AuthorizeAsync(server, $"https://client-{i}.example.com/metadata.json", $"https://client-{i}.example.com/callback");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        using var eleventh = await AuthorizeAsync(server, "https://client-10.example.com/metadata.json", "https://client-10.example.com/callback");
        Assert.Equal(HttpStatusCode.BadRequest, eleventh.StatusCode);
        Assert.Equal(10, handler.Calls);
        Assert.Contains(server.Logs.Lines, line => line.Contains("not fetched: more than 10 fetches in the last minute"));

        // The limit is not a failure of that client: a minute later it is fetched, not answered from a failure cache.
        server.Clock.Advance(TimeSpan.FromMinutes(1));
        using var later = await AuthorizeAsync(server, "https://client-10.example.com/metadata.json", "https://client-10.example.com/callback");
        Assert.Equal(HttpStatusCode.OK, later.StatusCode);
        Assert.Equal(11, handler.Calls);
    }

    [Fact]
    public async Task Requests_for_the_same_document_at_the_same_time_share_one_fetch()
    {
        var release = new TaskCompletionSource();
        var handler = new StubHandler(async (_, _) =>
        {
            await release.Task;
            return Json(Document());
        });
        using var server = ServerWith(handler);

        var requests = Enumerable.Range(0, 5).Select(_ => AuthorizeAsync(server)).ToList();
        await WaitUntilAsync(() => handler.Calls == 1);
        await Task.Delay(100, Cancel);
        release.SetResult();
        var responses = await Task.WhenAll(requests);

        Assert.All(responses, response => Assert.Equal(HttpStatusCode.OK, response.StatusCode));
        Assert.Equal(1, handler.Calls);
        foreach (var response in responses)
        {
            response.Dispose();
        }
    }

    // ---- R10: what the document must say (test 9) ----

    [Theory]
    [InlineData("https://client.example.com/oauth/metadata.json/")]
    [InlineData("https://CLIENT.example.com/oauth/metadata.json")]
    [InlineData("https://client.example.com/oauth/other.json")]
    [InlineData("https://other.example.com/oauth/metadata.json")]
    public async Task A_document_whose_client_id_is_not_exactly_the_fetched_URL_is_refused(string documentClientId)
    {
        using var server = ServerWith(new StubHandler(_ => Json(Document(documentClientId))));

        await AssertRefusedAsync(server, "refused: the document's client_id is not the URL it was fetched from.");
    }

    [Theory]
    [InlineData("https://other.example.com/callback")]
    [InlineData("https://evil.client.example.com/callback")]
    [InlineData("https://client.example.com.evil.example/callback")]
    [InlineData("https://example.com/callback")]
    [InlineData("http://client.example.com/callback")]
    [InlineData("https://client.example.com/callback#fragment")]
    [InlineData("https://user@client.example.com/callback")]
    [InlineData("com.example.client:/callback")]
    [InlineData("https://client.example.com/callback,https://other.example.com/callback")]
    public async Task A_document_with_a_redirect_URI_on_another_host_is_refused(string redirectUris)
    {
        using var server = ServerWith(new StubHandler(_ => Json(Document(ClientId, "none", redirectUris.Split(',')))));

        await AssertRefusedAsync(server, "refused: a redirect URI is not https on the client's own host.");
    }

    [Fact]
    public async Task A_document_may_list_loopback_redirect_URIs_next_to_its_own_host()
    {
        using var server = ServerWith(new StubHandler(_ => Json(Document(ClientId, "none", Redirect, "http://127.0.0.1/callback", "http://localhost:7777/callback"))));

        using var own = await AuthorizeAsync(server);
        using var loopback = await AuthorizeAsync(server, redirectUri: "http://127.0.0.1:51234/callback");
        using var unlisted = await AuthorizeAsync(server, redirectUri: "https://client.example.com/other");

        Assert.Equal(HttpStatusCode.OK, own.StatusCode);
        Assert.Equal(HttpStatusCode.OK, loopback.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, unlisted.StatusCode);
    }

    [Theory]
    [InlineData("""{"client_id":"https://client.example.com/oauth/metadata.json"}""", "redirect_uris is missing or has more than 10 entries")]
    [InlineData("""{"client_id":"https://client.example.com/oauth/metadata.json","redirect_uris":[]}""", "redirect_uris is missing or has more than 10 entries")]
    [InlineData("""{"client_id":"https://client.example.com/oauth/metadata.json","redirect_uris":"https://client.example.com/callback"}""", "redirect_uris is missing or has more than 10 entries")]
    [InlineData("""{"client_id":"https://client.example.com/oauth/metadata.json","redirect_uris":[42]}""", "a redirect URI is not https on the client's own host")]
    [InlineData("""{"redirect_uris":["https://client.example.com/callback"]}""", "the document's client_id is not the URL it was fetched from")]
    [InlineData("""{"client_id":42,"redirect_uris":["https://client.example.com/callback"]}""", "the document's client_id is not the URL it was fetched from")]
    [InlineData("""["https://client.example.com/oauth/metadata.json"]""", "the document's client_id is not the URL it was fetched from")]
    [InlineData("""{"client_id":"https://client.example.com/oauth/metadata.json","redirect_uris":["https://client.example.com/callback"]""", "the document is not valid JSON")]
    [InlineData("<html>not json</html>", "the document is not valid JSON")]
    [InlineData("", "the document is not valid JSON")]
    public async Task A_malformed_document_is_refused(string document, string reason)
    {
        using var server = ServerWith(new StubHandler(_ => Json(document)));

        await AssertRefusedAsync(server, $"refused: {reason}.");
    }

    [Fact]
    public async Task A_document_with_more_than_ten_redirect_URIs_is_refused()
    {
        var uris = Enumerable.Range(0, 11).Select(i => $"https://client.example.com/callback/{i}").ToArray();
        using var server = ServerWith(new StubHandler(_ => Json(Document(ClientId, "none", uris))));

        await AssertRefusedAsync(server, "refused: redirect_uris is missing or has more than 10 entries.");
    }

    [Theory]
    [InlineData("client_secret_basic", false)]
    [InlineData("client_secret_post", false)]
    [InlineData("private_key_jwt", false)]
    [InlineData("none", true)]
    [InlineData(null, true)]
    public async Task Only_public_clients_are_accepted(string? authMethod, bool accepted)
    {
        using var server = ServerWith(new StubHandler(_ => Json(Document(ClientId, authMethod))));

        using var response = await AuthorizeAsync(server);

        Assert.Equal(accepted ? HttpStatusCode.OK : HttpStatusCode.BadRequest, response.StatusCode);
        if (!accepted)
        {
            Assert.Contains(server.Logs.Lines, line => line.Contains("refused: token_endpoint_auth_method is not none."));
        }
    }

    [Fact]
    public async Task The_fetch_asks_for_JSON_with_a_plain_GET_and_sends_nothing_of_the_owner()
    {
        HttpRequestMessage? seen = null;
        var handler = new StubHandler(request =>
        {
            seen = request;
            return Json(Document());
        });
        using var server = ServerWith(handler);

        using var response = await AuthorizeAsync(server, cookie: "__Host-no2sql_owner=some-session");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(HttpMethod.Get, seen!.Method);
        Assert.Equal(ClientId, seen.RequestUri!.AbsoluteUri);
        Assert.Equal("application/json", seen.Headers.Accept.Single().MediaType);
        Assert.Null(seen.Content);
        Assert.False(seen.Headers.Contains("Cookie"));
        Assert.Null(seen.Headers.Authorization);
        Assert.False(seen.Headers.Contains("X-Forwarded-For"));
    }

    // ---- R13: the pages for a metadata-document client, and re-approval ----

    [Fact]
    public async Task The_pages_name_the_verified_host_and_never_the_name_the_document_claims()
    {
        var document = JsonNode.Parse(Document())!;
        document["client_name"] = "Your bank <script>alert(1)</script>";
        using var server = ServerWith(new StubHandler(_ => Json(document.ToJsonString())));

        using var authorize = await AuthorizeAsync(server);
        var loginPage = await authorize.Content.ReadAsStringAsync(Cancel);
        using var login = await server.LoginAsync(loginPage, server.Password);
        var consentPage = await login.Content.ReadAsStringAsync(Cancel);

        foreach (var page in new[] { loginPage, consentPage })
        {
            Assert.Contains("<strong>client.example.com</strong>", page);
            Assert.DoesNotContain("Unverified client", page);
            Assert.DoesNotContain("Your bank", page);
            Assert.DoesNotContain("<script", page);
        }

        Assert.Contains("If you approve, the authorization is sent to <strong>client.example.com</strong>.", consentPage);
    }

    [Fact]
    public async Task A_metadata_document_client_signs_in_and_its_tokens_carry_its_URL()
    {
        using var server = ServerWith(new StubHandler(_ => Json(Document())));

        var signedIn = await server.SignInAsync(ClientId, redirectUri: Redirect);

        Assert.Equal(ClientId, (string)BuiltinAuthServer.Decode(signedIn.AccessToken).Payload["client_id"]!);
        Assert.Equal(HttpStatusCode.OK, await server.McpStatusAsync(signedIn.AccessToken));
        Assert.Equal(HttpStatusCode.OK, (await server.RefreshAsync(signedIn.RefreshToken, ClientId)).Status);
        Assert.Empty(ClientStore.ReadAll(server.Directory).Clients);   // nothing is registered for it
    }

    [Fact]
    public async Task An_approved_metadata_document_client_skips_the_consent_page_for_30_days_and_only_for_the_same_redirect_URI()
    {
        const string second = "https://client.example.com/callback2";
        using var server = ServerWith(new StubHandler(_ => Json(Document(ClientId, "none", Redirect, second))));

        // First time: login and consent.
        using var first = await AuthorizeAsync(server);
        using var firstLogin = await server.LoginAsync(await first.Content.ReadAsStringAsync(Cancel), server.Password);
        Assert.Equal(HttpStatusCode.OK, firstLogin.StatusCode);
        Assert.Contains("Allow access to your databases?", await firstLogin.Content.ReadAsStringAsync(Cancel));
        using var approved = await server.ConsentAsync(await firstLogin.Content.ReadAsStringAsync(Cancel), BuiltinAuthServer.SessionCookie(firstLogin));
        Assert.Equal(HttpStatusCode.SeeOther, approved.StatusCode);

        // 29 days later: the password is still asked for, the consent page is not.
        server.Clock.Advance(TimeSpan.FromDays(29));
        using var again = await AuthorizeAsync(server);
        Assert.Equal(HttpStatusCode.OK, again.StatusCode);
        Assert.Contains("Owner password", await again.Content.ReadAsStringAsync(Cancel));
        using var againLogin = await server.LoginAsync(await again.Content.ReadAsStringAsync(Cancel), server.Password);
        Assert.Equal(HttpStatusCode.SeeOther, againLogin.StatusCode);
        Assert.StartsWith(Redirect + "?code=", againLogin.Headers.Location!.AbsoluteUri);
        Assert.Equal("state-123", BuiltinAuthServer.FromLocation(againLogin, "state"));
        Assert.Contains(server.Logs.Lines, line => line.Contains("re-approved from the owner's approval of the last 30 days"));

        // Another redirect URI of the same client was never approved: consent again.
        using var other = await AuthorizeAsync(server, redirectUri: second);
        using var otherLogin = await server.LoginAsync(await other.Content.ReadAsStringAsync(Cancel), server.Password);
        Assert.Equal(HttpStatusCode.OK, otherLogin.StatusCode);
        Assert.Contains("Allow access to your databases?", await otherLogin.Content.ReadAsStringAsync(Cancel));

        // 30 days after the last approval of the first one (which was renewed on day 29): consent again.
        server.Clock.Advance(TimeSpan.FromDays(30));
        using var late = await AuthorizeAsync(server);
        using var lateLogin = await server.LoginAsync(await late.Content.ReadAsStringAsync(Cancel), server.Password);
        Assert.Equal(HttpStatusCode.OK, lateLogin.StatusCode);
        Assert.Contains("Allow access to your databases?", await lateLogin.Content.ReadAsStringAsync(Cancel));
    }

    [Fact]
    public async Task A_wrong_password_never_reaches_a_remembered_approval()
    {
        using var server = ServerWith(new StubHandler(_ => Json(Document())));
        await server.AuthorizeFullyAsync(ClientId, Redirect);

        using var authorize = await AuthorizeAsync(server);
        using var login = await server.LoginAsync(await authorize.Content.ReadAsStringAsync(Cancel), "not-the-password");

        Assert.Equal(HttpStatusCode.Unauthorized, login.StatusCode);
        Assert.Null(login.Headers.Location);
    }

    [Theory]
    [InlineData("revoke")]
    [InlineData("revoke-all")]
    public async Task Revoking_forgets_a_remembered_approval(string command)
    {
        using var server = ServerWith(new StubHandler(_ => Json(Document())));
        var signedIn = await server.SignInAsync(ClientId, redirectUri: Redirect);

        var (exitCode, _, _) = command == "revoke" ? server.Cli("revoke", ClientId) : server.Cli("revoke-all");
        server.Clock.Advance(TimeSpan.FromSeconds(1));

        Assert.Equal(0, exitCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await server.RefreshAsync(signedIn.RefreshToken, ClientId)).Status);
        using var authorize = await AuthorizeAsync(server);
        using var login = await server.LoginAsync(await authorize.Content.ReadAsStringAsync(Cancel), server.Password);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        Assert.Contains("Allow access to your databases?", await login.Content.ReadAsStringAsync(Cancel));
    }

    [Fact]
    public async Task The_command_line_lists_a_metadata_document_client_with_its_approval()
    {
        using var server = ServerWith(new StubHandler(_ => Json(Document())));
        await server.SignInAsync(ClientId, redirectUri: Redirect);

        var (_, output, _) = server.Cli("list");

        Assert.Contains($"  {ClientId}  client.example.com approved 2026-11-25 12:00 UTC; 1 live grant(s)", output);
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        var deadline = Stopwatch.StartNew();
        while (!condition())
        {
            Assert.True(deadline.Elapsed < TimeSpan.FromSeconds(10), "the condition was not reached in 10 s");
            await Task.Delay(10, Cancel);
        }
    }

    private sealed class StubResolver(Func<string, IPAddress[]> answer) : IHostResolver
    {
        private readonly List<string> _hosts = [];

        public IReadOnlyList<string> Hosts { get { lock (_hosts) { return [.. _hosts]; } } }

        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken)
        {
            lock (_hosts)
            {
                _hosts.Add(host);
            }

            return Task.FromResult(answer(host));
        }
    }

    private sealed class RecordingPolicy : ICimdAddressPolicy
    {
        private readonly List<IPAddress> _asked = [];

        public IReadOnlyList<IPAddress> Asked { get { lock (_asked) { return [.. _asked]; } } }

        public bool IsAllowed(IPAddress address)
        {
            lock (_asked)
            {
                _asked.Add(address);
            }

            return true;
        }
    }

    // A response body without a known length.
    private sealed class UnseekableStream(byte[] data) : MemoryStream(data)
    {
        public override bool CanSeek => false;
    }

    // A response body that never delivers a byte.
    private sealed class StallingStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await Task.Delay(Timeout.Infinite, cancellationToken);
            return 0;
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
