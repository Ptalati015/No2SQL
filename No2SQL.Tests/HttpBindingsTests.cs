using No2SQL.Hosting;

namespace No2SQL.Tests;

/// <summary>NO2SQL_HTTP_URLS: what is accepted, and which addresses count as reachable from other machines.</summary>
public class HttpBindingsTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void The_default_is_loopback_port_8787(string? value)
    {
        Assert.True(HttpBindings.TryParse(value, out var bindings, out var error));
        Assert.Null(error);
        var binding = Assert.Single(bindings);
        Assert.Equal("http://127.0.0.1:8787", binding.DisplayUrl);
        Assert.True(binding.IsLoopback);
    }

    [Theory]
    [InlineData("http://127.0.0.1:9000", "http://127.0.0.1:9000")]
    [InlineData("http://127.5.5.5:9000", "http://127.5.5.5:9000")]
    [InlineData("http://[::1]:9000", "http://[::1]:9000")]
    [InlineData("http://localhost:9000", "http://localhost:9000")]
    [InlineData("HTTP://LOCALHOST:9000", "http://localhost:9000")]
    public void Loopback_addresses_are_not_exposed(string value, string displayUrl)
    {
        Assert.True(HttpBindings.TryParse(value, out var bindings, out _));
        var binding = Assert.Single(bindings);
        Assert.True(binding.IsLoopback);
        Assert.Equal(displayUrl, binding.DisplayUrl);
    }

    [Theory]
    [InlineData("http://0.0.0.0:8787")]
    [InlineData("http://[::]:8787")]
    [InlineData("http://*:8787")]
    [InlineData("http://+:8787")]
    [InlineData("http://192.168.1.20:8787")]
    [InlineData("http://10.0.0.5:8787")]
    [InlineData("http://example.com:8787")]              // a host name makes Kestrel listen on every interface
    [InlineData("http://localhost.example.com:8787")]
    [InlineData("http://127.0.0.1.nip.io:8787")]
    public void Everything_else_counts_as_reachable_from_other_machines(string value)
    {
        Assert.True(HttpBindings.TryParse(value, out var bindings, out _));
        Assert.False(Assert.Single(bindings).IsLoopback);
    }

    [Fact]
    public void Several_addresses_are_classified_one_by_one()
    {
        Assert.True(HttpBindings.TryParse("http://127.0.0.1:8787; http://0.0.0.0:8788;", out var bindings, out _));

        Assert.Equal(2, bindings.Count);
        Assert.True(bindings[0].IsLoopback);
        Assert.False(bindings[1].IsLoopback);
        Assert.Equal(8788, bindings[1].Port);
    }

    [Theory]
    [InlineData("https://127.0.0.1:8787", "supports http:// addresses only")]
    [InlineData("http://127.0.0.1:8787/mcp", "must not contain a path")]
    [InlineData("http://unix:/tmp/no2sql.sock", "supports TCP addresses only")]
    [InlineData("127.0.0.1:8787", "is not a URL")]
    [InlineData("http://127.0.0.1:0", "port outside 1-65535")]
    [InlineData("http://127.0.0.1:70000", "port outside 1-65535")]
    [InlineData(";;", "contains no address")]
    public void Unusable_values_are_refused_with_a_message_that_names_the_variable(string value, string expectedPart)
    {
        Assert.False(HttpBindings.TryParse(value, out _, out var error));
        Assert.StartsWith("NO2SQL_HTTP_URLS ", error);
        Assert.Contains(expectedPart, error);
    }

    [Fact]
    public void The_error_never_repeats_the_value()
    {
        // A URL can carry credentials (http://user:password@host); the message must not echo them.
        var password = Guid.NewGuid().ToString("N");
        Assert.False(HttpBindings.TryParse($"https://admin:{password}@10.0.0.5:8787", out _, out var error));
        Assert.DoesNotContain(password, error);
        Assert.DoesNotContain("10.0.0.5", error);
    }
}
