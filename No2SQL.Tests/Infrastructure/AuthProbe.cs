using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using No2SQL.Hosting;

namespace No2SQL.Tests.Infrastructure;

/// <summary>Runs the /mcp authentication scheme on one Authorization header and returns the caller it builds.</summary>
internal static class AuthProbe
{
    /// <returns>The authenticated caller, or null when the header is not accepted.</returns>
    public static async Task<ClaimsPrincipal?> AuthenticateAsync(No2SqlHttpApp app, string authorization)
    {
        using var scope = app.Services.CreateScope();
        var context = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        context.Request.Headers.Authorization = authorization;
        var result = await context.AuthenticateAsync(HttpAuth.Scheme);
        return result.Succeeded ? result.Principal : null;
    }
}
