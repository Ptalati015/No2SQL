using System.Net;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using No2SQL.Hosting;
using No2SQL.Tests.Infrastructure;

namespace No2SQL.Tests;

/// <summary>
/// HTTP mode writes no file of its own. ASP.NET Core Data Protection would: its start-up service creates a
/// key ring under the home directory, which fails on a read-only container file system. Sign-in does not
/// use it, so it must not be registered.
/// </summary>
public sealed class SignInServicesTests
{
    private static CancellationToken Cancel => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData("none")]
    [InlineData("bearer token")]
    [InlineData("identity provider")]
    [InlineData("built-in sign-in")]
    public async Task No_sign_in_mode_registers_Data_Protection_or_a_start_up_service_for_it(string mode)
    {
        const string token = "0123456789abcdef0123456789abcdef-test-token";
        var idp = new TestIdentityProvider();
        using var builtin = mode == "built-in sign-in" ? new BuiltinAuthServer() : null;
        using var app = mode switch
        {
            "none" => new No2SqlHttpApp(),
            "bearer token" => new No2SqlHttpApp(auth: new HttpAuthOptions { StaticToken = token }),
            "identity provider" => new No2SqlHttpApp(idp.Register, auth: TestIdentityProvider.Options()),
            _ => null,
        };
        using var client = app?.CreateClient() ?? builtin!.Client;   // the host and every start-up service have started
        var services = app?.Services ?? builtin!.Services;

        Assert.Null(services.GetService<IDataProtectionProvider>());
        Assert.DoesNotContain(services.GetServices<IHostedService>(), service => service.GetType().FullName!.Contains("DataProtection", StringComparison.Ordinal));

        // Sign-in still works without it.
        var bearer = mode switch
        {
            "bearer token" => token,
            "identity provider" => idp.Token(issuedAt: DateTime.UtcNow),
            "built-in sign-in" => (await builtin!.SignInAsync()).AccessToken,
            _ => null,
        };
        var reply = await client.RpcAsync("tools/list", configure: request =>
        {
            if (bearer is not null)
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
            }
        }, cancellationToken: Cancel);
        Assert.Equal(HttpStatusCode.OK, reply.Http.StatusCode);
    }
}
