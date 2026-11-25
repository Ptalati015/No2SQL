using No2SQL.Hosting;

namespace No2SQL.Tests;

/// <summary>Reading NO2SQL_HTTP_TOKEN, NO2SQL_OAUTH_* and NO2SQL_PUBLIC_URL, and the start-up rules.</summary>
public class HttpAuthOptionsTests
{
    // A fresh random token per run, so no credential-shaped literal sits in the repository.
    private static readonly string GoodToken = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));

    private static bool Parse(Dictionary<string, string> variables, out HttpAuthOptions options, out string? error) =>
        HttpAuthOptions.TryParse(name => variables.GetValueOrDefault(name), out options, out error);

    [Fact]
    public void Nothing_set_means_no_sign_in()
    {
        Assert.True(Parse([], out var options, out var error));
        Assert.Null(error);
        Assert.False(options.RequiresSignIn);
        Assert.Null(options.ResourceMetadataUrl);
    }

    [Fact]
    public void ToString_never_prints_the_token()
    {
        Assert.True(Parse(new() { ["NO2SQL_HTTP_TOKEN"] = GoodToken }, out var options, out _));

        Assert.DoesNotContain(GoodToken, options.ToString(), StringComparison.Ordinal);
        Assert.Contains("StaticToken = [set]", options.ToString(), StringComparison.Ordinal);
        Assert.Contains("StaticToken = [unset]", HttpAuthOptions.None.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void A_random_token_is_accepted()
    {
        Assert.True(Parse(new() { ["NO2SQL_HTTP_TOKEN"] = GoodToken }, out var options, out _));
        Assert.True(options.HasStaticToken);
        Assert.False(options.HasAuthority);
        Assert.Null(options.ResourceMetadataUrl);   // no authorization server, so nothing to publish
    }

    [Theory]
    [InlineData("short", "at least 32 characters")]
    [InlineData("0123456789abcdef0123456789abcde", "at least 32 characters")]                 // 31 bytes
    [InlineData("has spaces in it and is long enough to pass", "may contain only")]
    [InlineData("<paste the output of openssl rand -base64 32>", "may contain only")]
    [InlineData("quoted\"token\"that-is-definitely-long-enough", "may contain only")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "looks like a placeholder")]
    [InlineData("abababababababababababababababababababab", "looks like a placeholder")]
    [InlineData("my-example-token-value-1234567890-qwerty", "looks like a placeholder")]
    [InlineData("CHANGEME-0123456789-abcdefghijklmnopqrstuv", "looks like a placeholder")]
    public void Weak_or_malformed_tokens_are_refused_without_repeating_them(string token, string expected)
    {
        Assert.False(Parse(new() { ["NO2SQL_HTTP_TOKEN"] = token }, out _, out var error));
        Assert.StartsWith("NO2SQL_HTTP_TOKEN ", error);
        Assert.Contains(expected, error);
        Assert.DoesNotContain(token, error);
    }

    [Fact]
    public void An_identity_provider_needs_the_public_url()
    {
        Assert.False(Parse(new() { ["NO2SQL_OAUTH_AUTHORITY"] = "https://login.example.com/" }, out _, out var error));
        Assert.Contains("needs NO2SQL_PUBLIC_URL", error);
    }

    [Fact]
    public void An_identity_provider_with_a_public_url_derives_every_url_from_configuration()
    {
        Assert.True(Parse(new()
        {
            ["NO2SQL_OAUTH_AUTHORITY"] = "https://login.example.com/tenant/v2.0",
            ["NO2SQL_PUBLIC_URL"] = "https://MCP.Example.com/",
        }, out var options, out _));

        Assert.Equal("https://login.example.com/tenant/v2.0", options.Authority);   // the issuer, exactly as given
        Assert.Equal("https://mcp.example.com/mcp", options.McpUrl);
        Assert.Equal("https://mcp.example.com/.well-known/oauth-protected-resource/mcp", options.ResourceMetadataUrl);
        Assert.Equal("mcp:tools", options.Scope);
    }

    [Theory]
    [InlineData("http://login.example.com/")]          // metadata and keys over https only
    [InlineData("http://localhost:8080/")]             // no loopback exception for the identity provider
    [InlineData("https://user:pw@login.example.com/")]
    [InlineData("https://login.example.com/?tenant=1")]
    [InlineData("login.example.com")]
    public void The_authority_must_be_a_plain_https_url(string authority)
    {
        Assert.False(Parse(new() { ["NO2SQL_OAUTH_AUTHORITY"] = authority, ["NO2SQL_PUBLIC_URL"] = "https://mcp.example.com" }, out _, out var error));
        Assert.StartsWith("NO2SQL_OAUTH_AUTHORITY must be", error);
    }

    [Theory]
    [InlineData("http://mcp.example.com", "must use https://")]
    [InlineData("http://10.0.0.5:8787", "must use https://")]
    [InlineData("https://mcp.example.com/mcp", "with no path")]
    [InlineData("https://mcp.example.com/base/", "with no path")]
    [InlineData("https://mcp.example.com/?x=1", "with no path")]
    [InlineData("ftp://mcp.example.com", "with no path")]
    [InlineData("mcp.example.com", "with no path")]
    public void The_public_url_is_an_https_origin(string publicUrl, string expected)
    {
        Assert.False(Parse(new() { ["NO2SQL_PUBLIC_URL"] = publicUrl }, out _, out var error));
        Assert.StartsWith("NO2SQL_PUBLIC_URL must", error);
        Assert.Contains(expected, error);
    }

    [Theory]
    [InlineData("http://localhost:8787", "http://localhost:8787/mcp")]
    [InlineData("http://127.0.0.1:8787/", "http://127.0.0.1:8787/mcp")]
    [InlineData("http://[::1]:8787", "http://[::1]:8787/mcp")]
    [InlineData("https://mcp.example.com:443", "https://mcp.example.com/mcp")]
    [InlineData("https://mcp.example.com:8443", "https://mcp.example.com:8443/mcp")]
    public void Plain_http_public_urls_are_for_this_machine_only(string publicUrl, string mcpUrl)
    {
        Assert.True(Parse(new() { ["NO2SQL_OAUTH_AUTHORITY"] = "https://login.example.com/", ["NO2SQL_PUBLIC_URL"] = publicUrl }, out var options, out var error), error);
        Assert.Equal(mcpUrl, options.McpUrl);
    }

    [Fact]
    public void The_required_scope_can_be_changed_for_an_identity_provider_only()
    {
        Assert.True(Parse(new() { ["NO2SQL_OAUTH_AUTHORITY"] = "https://login.example.com/", ["NO2SQL_PUBLIC_URL"] = "https://mcp.example.com", ["NO2SQL_OAUTH_SCOPE"] = "api://no2sql/tools.read" }, out var options, out _));
        Assert.Equal("api://no2sql/tools.read", options.Scope);

        Assert.False(Parse(new() { ["NO2SQL_OAUTH_SCOPE"] = "mcp:tools" }, out _, out var alone));
        Assert.Contains("only applies together with NO2SQL_OAUTH_AUTHORITY", alone);

        Assert.False(Parse(new() { ["NO2SQL_OAUTH_AUTHORITY"] = "https://login.example.com/", ["NO2SQL_PUBLIC_URL"] = "https://mcp.example.com", ["NO2SQL_OAUTH_SCOPE"] = "two scopes" }, out _, out var two));
        Assert.Contains("one scope name", two);
    }

    [Fact]
    public void Only_one_authorization_server()
    {
        Assert.False(Parse(new() { ["NO2SQL_OAUTH_BUILTIN"] = "true", ["NO2SQL_OAUTH_AUTHORITY"] = "https://login.example.com/", ["NO2SQL_PUBLIC_URL"] = "https://mcp.example.com" }, out _, out var both));
        Assert.Contains("not both", both);

        Assert.False(Parse(new() { ["NO2SQL_OAUTH_BUILTIN"] = "yes" }, out _, out var bad));
        Assert.Equal("NO2SQL_OAUTH_BUILTIN must be 'true' or 'false'.", bad);

        Assert.True(Parse(new() { ["NO2SQL_OAUTH_BUILTIN"] = "false" }, out var off, out _));
        Assert.False(off.RequiresSignIn);
    }

    private static readonly string HomeVariable = OperatingSystem.IsWindows() ? "USERPROFILE" : "HOME";
    private static readonly string Home = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "no2sql-home"));

    private static Dictionary<string, string> Builtin(params (string Name, string Value)[] more)
    {
        var variables = new Dictionary<string, string> { ["NO2SQL_OAUTH_BUILTIN"] = "true", ["NO2SQL_PUBLIC_URL"] = "https://mcp.example.com", [HomeVariable] = Home };
        foreach (var (name, value) in more)
        {
            variables[name] = value;
        }

        return variables;
    }

    [Fact]
    public void The_built_in_server_needs_only_the_public_URL()
    {
        Assert.True(Parse(Builtin(), out var options, out var error), error);
        Assert.True(options.Builtin && options.UsesJwt && options.RequiresSignIn);
        Assert.False(options.HasAuthority);
        Assert.Equal("https://mcp.example.com", options.Issuer);
        Assert.Equal("https://mcp.example.com/mcp", options.McpUrl);
        Assert.Equal("https://mcp.example.com/.well-known/oauth-protected-resource/mcp", options.ResourceMetadataUrl);
        Assert.Equal(Path.Combine(Home, ".no2sql"), options.DataDirectory);
        Assert.Null(options.OwnerPassword);
        Assert.Equal(TimeSpan.FromMinutes(60), options.AccessTokenLifetime);
    }

    [Fact]
    public void The_built_in_server_without_a_public_URL_is_refused()
    {
        var variables = Builtin();
        variables.Remove("NO2SQL_PUBLIC_URL");
        Assert.False(Parse(variables, out _, out var error));
        Assert.Contains("needs NO2SQL_PUBLIC_URL", error);
    }

    [Fact]
    public void The_built_in_server_on_a_plain_http_public_URL_is_refused_unless_loopback()
    {
        Assert.False(Parse(Builtin(("NO2SQL_PUBLIC_URL", "http://mcp.example.com")), out _, out var error));
        Assert.Contains("must use https://", error);
        Assert.True(Parse(Builtin(("NO2SQL_PUBLIC_URL", "http://localhost:8787")), out var local, out _));
        Assert.Equal("http://localhost:8787", local.Issuer);
    }

    [Fact]
    public void The_static_token_may_be_combined_with_the_built_in_server()
    {
        Assert.True(Parse(Builtin(("NO2SQL_HTTP_TOKEN", GoodToken)), out var options, out _));
        Assert.True(options.HasStaticToken && options.Builtin);
    }

    [Theory]
    [InlineData("short-pass1")]      // 11 characters
    [InlineData("12345678901")]
    public void An_owner_password_shorter_than_12_characters_is_refused(string password)
    {
        Assert.False(Parse(Builtin(("NO2SQL_OWNER_PASSWORD", password)), out _, out var error));
        Assert.Equal("NO2SQL_OWNER_PASSWORD must be at least 12 characters. Leave it unset to have a strong password generated at the first start.", error);
        Assert.DoesNotContain(password, error);
    }

    [Fact]
    public void An_owner_password_is_kept_exactly_and_never_printed()
    {
        var password = " correct horse battery staple ";
        Assert.True(Parse(Builtin(("NO2SQL_OWNER_PASSWORD", password)), out var options, out _));
        Assert.Equal(password, options.OwnerPassword);
        Assert.Contains("OwnerPassword = [set]", options.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("horse", options.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("NO2SQL_OWNER_PASSWORD", "a-long-enough-password")]
    [InlineData("NO2SQL_OAUTH_ACCESS_TOKEN_MINUTES", "30")]
    public void Built_in_settings_without_the_built_in_server_are_refused(string name, string value)
    {
        Assert.False(Parse(new() { [name] = value }, out _, out var error));
        Assert.Equal($"{name} only applies together with NO2SQL_OAUTH_BUILTIN=true.", error);
    }

    [Theory]
    [InlineData("4")]
    [InlineData("1441")]
    [InlineData("-5")]
    [InlineData("60m")]
    [InlineData("1e2")]
    public void The_access_token_lifetime_must_be_5_to_1440_minutes(string value)
    {
        Assert.False(Parse(Builtin(("NO2SQL_OAUTH_ACCESS_TOKEN_MINUTES", value)), out _, out var error));
        Assert.Contains("from 5 to 1440", error);
    }

    [Fact]
    public void The_access_token_lifetime_can_be_set()
    {
        Assert.True(Parse(Builtin(("NO2SQL_OAUTH_ACCESS_TOKEN_MINUTES", "1440")), out var options, out _));
        Assert.Equal(TimeSpan.FromDays(1), options.AccessTokenLifetime);
    }

    [Fact]
    public void The_data_directory_must_be_absolute_and_has_a_default_only_with_a_home_directory()
    {
        Assert.True(Parse(Builtin(("NO2SQL_DATA_DIR", Path.Combine(Home, "state"))), out var options, out _));
        Assert.Equal(Path.Combine(Home, "state"), options.DataDirectory);

        Assert.False(Parse(Builtin(("NO2SQL_DATA_DIR", "relative/dir")), out _, out var relative));
        Assert.Equal("NO2SQL_DATA_DIR must be an absolute path.", relative);

        var noHome = Builtin();
        noHome.Remove(HomeVariable);
        Assert.False(Parse(noHome, out _, out var missing));
        Assert.Contains("Set NO2SQL_DATA_DIR", missing);
    }

    [Fact]
    public void A_data_directory_without_the_built_in_server_is_ignored()
    {
        // The Docker image sets NO2SQL_DATA_DIR for every deployment, including token-only ones.
        Assert.True(Parse(new() { ["NO2SQL_DATA_DIR"] = "/data", ["NO2SQL_HTTP_TOKEN"] = GoodToken }, out var options, out _));
        Assert.Null(options.DataDirectory);
    }

    [Fact]
    public void The_static_token_may_be_combined_with_an_identity_provider()
    {
        Assert.True(Parse(new() { ["NO2SQL_HTTP_TOKEN"] = GoodToken, ["NO2SQL_OAUTH_AUTHORITY"] = "https://login.example.com/", ["NO2SQL_PUBLIC_URL"] = "https://mcp.example.com" }, out var options, out _));
        Assert.True(options.HasStaticToken && options.HasAuthority);
    }

    [Theory]
    [InlineData("http://127.0.0.1:8787", false, false, null)]                       // loopback, anonymous: allowed (with a warning)
    [InlineData("http://0.0.0.0:8787", false, false, "Refusing to start")]          // reachable, no sign-in
    [InlineData("http://0.0.0.0:8787", true, false, null)]                          // reachable, explicitly anonymous
    [InlineData("http://0.0.0.0:8787", false, true, null)]                          // reachable with sign-in
    [InlineData("http://example.com:8787", false, true, null)]
    [InlineData("http://127.0.0.1:8787", true, true, "cannot be combined")]
    [InlineData("http://0.0.0.0:8787", true, true, "cannot be combined")]
    public void Start_up_rules(string urls, bool allowAnonymous, bool withToken, string? refusal)
    {
        Assert.True(HttpBindings.TryParse(urls, out var bindings, out _));
        var auth = withToken ? new HttpAuthOptions { StaticToken = GoodToken } : HttpAuthOptions.None;

        var result = HttpServer.StartupRefusal(bindings, auth, allowAnonymous);

        if (refusal is null)
        {
            Assert.Null(result);
        }
        else
        {
            Assert.Contains(refusal, result);
        }
    }

    [Fact]
    public void The_built_in_server_counts_as_sign_in_for_the_start_up_rules()
    {
        Assert.True(HttpBindings.TryParse("http://0.0.0.0:8787", out var bindings, out _));
        Assert.True(Parse(Builtin(), out var builtin, out _));

        Assert.Null(HttpServer.StartupRefusal(bindings, builtin, allowAnonymous: false));
        Assert.Contains("cannot be combined", HttpServer.StartupRefusal(bindings, builtin, allowAnonymous: true));
        Assert.Contains("NO2SQL_OAUTH_BUILTIN=true", HttpServer.StartupRefusal(bindings, HttpAuthOptions.None, allowAnonymous: false));
    }
}
