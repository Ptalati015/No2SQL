using System.Net;
using No2SQL.Hosting;
using No2SQL.Tests.Infrastructure;

namespace No2SQL.Tests;

public class HealthEndpointTests
{
    [Fact]
    public async Task Healthz_answers_200_with_the_fixed_body_and_nothing_else()
    {
        using var app = new No2SqlHttpApp();   // NO2SQL_MONGO not set: the health check must not need it
        using var client = app.CreateClient();

        using var response = await client.GetAsync("/healthz", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("{\"status\":\"ok\"}", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        Assert.Equal("{\"status\":\"ok\"}", HttpServer.HealthBody);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.ToString());
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
    }

    [Fact]
    public async Task Healthz_is_the_same_when_the_connection_string_is_unusable()
    {
        using var app = new No2SqlHttpApp(mongoConnectionString: "not a connection string");
        using var client = app.CreateClient();

        using var response = await client.GetAsync("/healthz", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(HttpServer.HealthBody, await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("POST")]
    [InlineData("PUT")]
    [InlineData("DELETE")]
    public async Task Healthz_accepts_GET_only(string method)
    {
        using var app = new No2SqlHttpApp();
        using var client = app.CreateClient();

        using var response = await client.SendAsync(new HttpRequestMessage(new HttpMethod(method), "/healthz"), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
    }
}
