using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using No2SQL.Hosting;

namespace No2SQL.Tests.Infrastructure;

/// <summary>
/// No2SQL's HTTP mode on an in-memory server: the same <see cref="HttpServer.ConfigureServices"/> and
/// <see cref="HttpServer.ConfigurePipeline"/> the real process runs, without Kestrel, a port or MongoDB.
/// Create one per test (or per test class) and dispose it.
/// </summary>
/// <example>
/// Replace a service for one test, for example the clock:
/// <code>
/// var clock = new FakeTimeProvider();
/// using var app = new No2SqlHttpApp(services => services.AddSingleton&lt;TimeProvider&gt;(clock));
/// </code>
/// </example>
internal sealed class No2SqlHttpApp : IDisposable
{
    private readonly Factory _factory;

    /// <param name="configureTestServices">Runs after the application's own registrations, so it can replace them.</param>
    /// <param name="mongoConnectionString">What NO2SQL_MONGO would hold. Null means "not set".</param>
    /// <param name="auth">The sign-in settings. Null means none (anonymous HTTP mode).</param>
    public No2SqlHttpApp(Action<IServiceCollection>? configureTestServices = null, string? mongoConnectionString = null, HttpAuthOptions? auth = null)
    {
        _factory = new Factory(mongoConnectionString, auth ?? HttpAuthOptions.None, configureTestServices);
    }

    /// <summary>The application's service provider.</summary>
    public IServiceProvider Services => _factory.Services;

    /// <summary>A client that talks to the in-memory server. Base address: http://localhost/.</summary>
    public HttpClient CreateClient() => _factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = false,
        HandleCookies = false,
    });

    public void Dispose() => _factory.Dispose();

    // Program is internal to No2SQL, so the factory is nested here rather than exposed.
    private sealed class Factory(string? mongoConnectionString, HttpAuthOptions auth, Action<IServiceCollection>? configureTestServices)
        : WebApplicationFactory<Program>
    {
        // No2SQL's entry point decides between stdio and HTTP from the command line and builds its
        // own Kestrel host, so the factory does not run it. It builds a plain host around the two
        // methods that make up HTTP mode; WebApplicationFactory then swaps in the in-memory server.
        protected override IHostBuilder CreateHostBuilder() =>
            new HostBuilder().ConfigureWebHost(web =>
            {
                web.ConfigureServices(services => HttpServer.ConfigureServices(services, mongoConnectionString, auth));
                web.Configure(HttpServer.ConfigurePipeline);
            });

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            if (configureTestServices is not null)
            {
                builder.ConfigureTestServices(configureTestServices);
            }
        }
    }
}
