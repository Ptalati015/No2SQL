using System.Text.Encodings.Web;

namespace No2SQL.Hosting.OAuth;

/// <summary>
/// The owner's pages: login, consent and error (threat model R13, R18). No scripts; every value that comes
/// from a request, a registration or a metadata document is HTML-encoded; the error page never shows a
/// redirect URI or a state value.
/// </summary>
internal static class OAuthPages
{
    public const string StylePath = "/oauth.css";

    public const string Stylesheet =
        "body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f5f5f4;color:#1c1917}" +
        "main{max-width:30rem;margin:3rem auto;padding:2rem;background:#fff;border:1px solid #d6d3d1;border-radius:.75rem}" +
        "h1{font-size:1.35rem;margin:0 0 1rem}p,li{line-height:1.5}.who{font-size:1.1rem}.warn{background:#fef3c7;border:1px solid #f59e0b;padding:.75rem;border-radius:.5rem}" +
        ".error{background:#fee2e2;border:1px solid #ef4444;padding:.75rem;border-radius:.5rem}" +
        "label{display:block;margin:1rem 0 .25rem;font-weight:600}input[type=password]{width:100%;box-sizing:border-box;padding:.6rem;font-size:1rem;border:1px solid #a8a29e;border-radius:.4rem}" +
        ".buttons{display:flex;gap:.75rem;margin-top:1.5rem}button{flex:1;padding:.7rem;font-size:1rem;border-radius:.4rem;border:1px solid #57534e;background:#fff;cursor:pointer}" +
        "button.primary{background:#1c1917;color:#fff}code{font-size:.9em}" +
        "@media (prefers-color-scheme:dark){body{background:#1c1917;color:#e7e5e4}main{background:#292524;border-color:#44403c}" +
        "button{background:#292524;color:#e7e5e4;border-color:#a8a29e}button.primary{background:#e7e5e4;color:#1c1917}" +
        ".warn{background:#422006;border-color:#b45309}.error{background:#450a0a;border-color:#b91c1c}input[type=password]{background:#1c1917;color:#e7e5e4}}";

    private static readonly HtmlEncoder Html = HtmlEncoder.Default;

    public static string Login(PendingAuthorization request, string? message) => Page("Sign in to No2SQL", $"""
        <h1>Sign in to No2SQL</h1>
        <p class="who">{Who(request.Client)} wants to connect to this No2SQL server.</p>
        {(request.Client.IsMetadataDocument ? "" : UnverifiedWarning)}
        {(message is null ? "" : $"<p class=\"error\">{Html.Encode(message)}</p>")}
        <form method="post" action="{OAuthServerEndpoints.LoginPath}">
        <input type="hidden" name="request" value="{Html.Encode(request.Id)}">
        <input type="hidden" name="csrf" value="{Html.Encode(request.LoginToken)}">
        <label for="password">Owner password</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
        <div class="buttons"><button class="primary" type="submit">Sign in</button></div>
        </form>
        """);

    public static string Consent(PendingAuthorization request) => Page("Allow access to your databases?", $"""
        <h1>Allow access to your databases?</h1>
        <p class="who">{Who(request.Client)} is asking for access.</p>
        {(request.Client.IsMetadataDocument ? "" : UnverifiedWarning)}
        <p>If you approve, the authorization is sent to <strong>{Html.Encode(RedirectUriRules.Describe(request.RedirectUri))}</strong>.</p>
        <p>It will be able to <strong>read your MongoDB databases through No2SQL until you revoke it</strong>
        (<code>No2SQL oauth revoke</code>).</p>
        <p>Requested access:</p>
        <ul>{string.Concat(request.Scope.Split(' ').Select(s => $"<li>{Html.Encode(DescribeScope(s))}</li>"))}</ul>
        <form method="post" action="{OAuthServerEndpoints.ConsentPath}">
        <input type="hidden" name="request" value="{Html.Encode(request.Id)}">
        <input type="hidden" name="csrf" value="{Html.Encode(request.ConsentToken)}">
        <div class="buttons">
        <button type="submit" name="decision" value="deny">Deny</button>
        <button class="primary" type="submit" name="decision" value="approve">Approve</button>
        </div>
        </form>
        """);

    public static string Error(string message) => Page("No2SQL sign-in", $"""
        <h1>This sign-in cannot continue</h1>
        <p class="error">{Html.Encode(message)}</p>
        <p>Close this page and start the connection again from your application.</p>
        """);

    private const string UnverifiedWarning =
        "<p class=\"warn\">No2SQL cannot check who this client is. Continue only if you started this connection yourself just now.</p>";

    // CIMD clients by their verified host; DCR clients as unverified, with the name they registered.
    private static string Who(ResolvedClient client) => client.IsMetadataDocument
        ? $"<strong>{Html.Encode(client.VerifiedHost!)}</strong>"
        : $"Unverified client: <strong>{Html.Encode(client.Name ?? "(no name)")}</strong>";

    private static string DescribeScope(string scope) => scope switch
    {
        "mcp:tools" => "mcp:tools: use the No2SQL tools (read-only)",
        "offline_access" => "offline_access: stay connected without signing in again",
        _ => scope,
    };

    private static string Page(string title, string body) => $"""
        <!doctype html>
        <html lang="en">
        <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{Html.Encode(title)}</title>
        <link rel="stylesheet" href="{StylePath}">
        </head>
        <body>
        <main>
        {body}
        </main>
        </body>
        </html>
        """;
}
