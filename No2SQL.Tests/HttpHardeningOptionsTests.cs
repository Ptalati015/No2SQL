using System.Net;
using No2SQL.Hosting;

namespace No2SQL.Tests;

/// <summary>P2-6 settings: defaults, overrides and the start-up refusals (criteria 6b, 12, 13).</summary>
public class HttpHardeningOptionsTests
{
    private static HttpHardeningOptions Parse(string? urls, Dictionary<string, string?>? variables = null)
    {
        Assert.True(HttpBindings.TryParse(urls, out var bindings, out var bindingError), bindingError);
        Assert.True(HttpHardeningOptions.TryParse(name => variables?.GetValueOrDefault(name), bindings, out var options, out var error), error);
        return options!;
    }

    private static string? ParseError(Dictionary<string, string?> variables, string? urls = null)
    {
        Assert.True(HttpBindings.TryParse(urls, out var bindings, out _));
        Assert.False(HttpHardeningOptions.TryParse(name => variables.GetValueOrDefault(name), bindings, out _, out var error));
        return error;
    }

    [Fact]
    public void Defaults_match_the_spec()
    {
        var options = Parse(null);

        Assert.Equal(["127.0.0.1", "localhost", "[::1]"], options.AllowedHosts);
        Assert.Equal(new HashSet<string> { "http://localhost:8787", "http://127.0.0.1:8787", "http://[::1]:8787" }, options.AllowedOrigins);
        Assert.Empty(options.TrustedProxies);
        Assert.Equal(1048576, options.MaxBodyBytes);
        Assert.Equal(TimeSpan.FromSeconds(120), options.RequestTimeout);
        Assert.Equal(60, options.RateLimitPerMinute);
        Assert.Equal(300, options.RateLimitPerIpPerMinute);
        Assert.Equal(16, options.MaxConcurrentCalls);
        Assert.Equal(256, options.MaxConnections);
        Assert.False(options.Hsts);
        Assert.Equal(TimeSpan.FromMinutes(1), options.RateLimitWindow);
        Assert.Empty(options.Warnings);
    }

    // 6b
    [Theory]
    [InlineData("http://0.0.0.0:8787")]
    [InlineData("http://[::]:8787")]
    [InlineData("http://*:8787")]
    [InlineData("http://+:8787")]
    public void A_wildcard_bind_allows_only_loopback_hosts_and_warns(string urls)
    {
        var options = Parse(urls);

        Assert.Equal(["localhost", "127.0.0.1", "[::1]"], options.AllowedHosts);
        Assert.Contains("http://localhost:8787", options.AllowedOrigins);
        var warning = Assert.Single(options.Warnings);
        Assert.Contains("Remote callers get 400 until NO2SQL_PUBLIC_URL or NO2SQL_HTTP_ALLOWED_HOSTS is set", warning);
    }

    [Fact]
    public void A_LAN_address_bind_allows_that_address()
    {
        var options = Parse("http://192.168.1.20:8787");

        Assert.Contains("192.168.1.20", options.AllowedHosts);
        Assert.Empty(options.Warnings);
    }

    [Fact]
    public void The_public_URL_sets_host_origin_and_HSTS()
    {
        var options = Parse("http://0.0.0.0:8787", new() { ["NO2SQL_PUBLIC_URL"] = "https://No2SQL.Example.com/" });

        Assert.Contains("no2sql.example.com", options.AllowedHosts);
        Assert.Contains("localhost", options.AllowedHosts);   // a sidecar probe on loopback still passes
        Assert.Contains("https://no2sql.example.com:443", options.AllowedOrigins);
        Assert.True(options.Hsts);
        Assert.Empty(options.Warnings);
        Assert.True(options.IsAllowedOrigin("https://no2sql.example.com"));
        Assert.True(options.IsAllowedOrigin("https://NO2SQL.example.com:443"));
        Assert.False(options.IsAllowedOrigin("https://no2sql.example.com:8443"));
        Assert.False(options.IsAllowedOrigin("http://no2sql.example.com"));
        Assert.False(options.IsAllowedOrigin("null"));
    }

    [Fact]
    public void Every_setting_can_be_overridden()
    {
        var options = Parse(null, new()
        {
            ["NO2SQL_HTTP_ALLOWED_HOSTS"] = "a.example, *.b.example",
            ["NO2SQL_HTTP_ALLOWED_ORIGINS"] = "https://a.example,http://localhost:3000",
            ["NO2SQL_HTTP_TRUSTED_PROXIES"] = "172.30.0.0/24, 10.0.0.7, ::1",
            ["NO2SQL_HTTP_MAX_BODY_BYTES"] = "65536",
            ["NO2SQL_HTTP_REQUEST_TIMEOUT_SECONDS"] = "30",
            ["NO2SQL_HTTP_RATE_LIMIT_PER_MINUTE"] = "10",
            ["NO2SQL_HTTP_RATE_LIMIT_PER_IP_PER_MINUTE"] = "20",
            ["NO2SQL_HTTP_MAX_CONCURRENT_CALLS"] = "4",
            ["NO2SQL_HTTP_MAX_CONNECTIONS"] = "50",
            ["NO2SQL_HTTP_HSTS"] = "true",
        });

        Assert.Equal(["a.example", "*.b.example"], options.AllowedHosts);
        Assert.Equal(new HashSet<string> { "https://a.example:443", "http://localhost:3000" }, options.AllowedOrigins);
        Assert.Equal([IPNetwork.Parse("172.30.0.0/24"), IPNetwork.Parse("10.0.0.7/32"), IPNetwork.Parse("::1/128")], options.TrustedProxies);
        Assert.Equal(65536, options.MaxBodyBytes);
        Assert.Equal(TimeSpan.FromSeconds(30), options.RequestTimeout);
        Assert.Equal(10, options.RateLimitPerMinute);
        Assert.Equal(20, options.RateLimitPerIpPerMinute);
        Assert.Equal(4, options.MaxConcurrentCalls);
        Assert.Equal(50, options.MaxConnections);
        Assert.True(options.Hsts);
    }

    // 13
    [Theory]
    [InlineData("*")]
    [InlineData("a.example,*")]
    public void A_star_in_allowed_hosts_refuses_to_start(string hosts)
    {
        var error = ParseError(new() { ["NO2SQL_HTTP_ALLOWED_HOSTS"] = hosts });

        Assert.StartsWith("NO2SQL_HTTP_ALLOWED_HOSTS must not contain '*'", error);
    }

    [Theory]
    [InlineData("NO2SQL_HTTP_ALLOWED_ORIGINS", "https://a.example/path")]
    [InlineData("NO2SQL_HTTP_ALLOWED_ORIGINS", "null")]
    [InlineData("NO2SQL_HTTP_ALLOWED_ORIGINS", "ftp://a.example")]
    [InlineData("NO2SQL_HTTP_TRUSTED_PROXIES", "proxy.internal")]
    [InlineData("NO2SQL_HTTP_TRUSTED_PROXIES", "10.0.0.0/33")]
    [InlineData("NO2SQL_HTTP_MAX_BODY_BYTES", "1MB")]
    [InlineData("NO2SQL_HTTP_MAX_BODY_BYTES", "100")]
    [InlineData("NO2SQL_HTTP_REQUEST_TIMEOUT_SECONDS", "0")]
    [InlineData("NO2SQL_HTTP_RATE_LIMIT_PER_MINUTE", "-1")]
    [InlineData("NO2SQL_HTTP_RATE_LIMIT_PER_IP_PER_MINUTE", "lots")]
    [InlineData("NO2SQL_HTTP_MAX_CONCURRENT_CALLS", "0")]
    [InlineData("NO2SQL_HTTP_MAX_CONNECTIONS", "1.5")]
    [InlineData("NO2SQL_HTTP_HSTS", "maybe")]
    [InlineData("NO2SQL_PUBLIC_URL", "no2sql.example.com")]
    public void A_bad_value_refuses_to_start_naming_the_variable(string variable, string value)
    {
        var error = ParseError(new() { [variable] = value });

        Assert.StartsWith(variable, error);
    }

    // 12
    [Fact]
    public void The_summary_lists_every_value_and_no_secret()
    {
        var summary = Parse(null, new()
        {
            ["NO2SQL_HTTP_TOKEN"] = "token-that-must-not-appear",
            ["NO2SQL_MONGO"] = "mongodb://u:pw-that-must-not-appear@h/",
        }).Summary();

        Assert.Equal(
            "allowed hosts 127.0.0.1,localhost,[::1]; allowed origins http://127.0.0.1:8787,http://[::1]:8787,http://localhost:8787; " +
            "trusted proxies none; max body 1048576 bytes; request timeout 120 s; rate limit 60/min per token, 300/min per IP; " +
            "max concurrent calls 16; max connections 256; HSTS off",
            summary);
    }

    [Fact]
    public void Bearer_tokens_are_hashed_before_they_become_a_rate_limit_key()
    {
        var key = HttpHardening.TokenPartitionKey("secret-token-value");

        Assert.Matches("^token:[0-9a-f]{32}$", key);
        Assert.DoesNotContain("secret-token-value", key);
        Assert.Equal(key, HttpHardening.TokenPartitionKey("secret-token-value"));
        Assert.NotEqual(key, HttpHardening.TokenPartitionKey("secret-token-valuf"));
    }
}
