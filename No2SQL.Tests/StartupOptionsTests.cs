using No2SQL.Hosting;

namespace No2SQL.Tests;

public class StartupOptionsTests
{
    [Theory]
    [InlineData(new string[0], null)]
    [InlineData(new string[0], "")]
    [InlineData(new string[0], "  ")]
    [InlineData(new string[0], "stdio")]
    [InlineData(new string[0], "STDIO")]
    public void Stdio_is_the_default(string[] args, string? variable)
    {
        Assert.True(StartupOptions.TryParse(args, variable, out var options, out var error));
        Assert.Null(error);
        Assert.Equal(TransportKind.Stdio, options.Transport);
        Assert.False(options.AllowAnonymous);
    }

    [Theory]
    [InlineData(new[] { "--http" }, null)]
    [InlineData(new[] { "--HTTP" }, null)]
    [InlineData(new string[0], "http")]
    [InlineData(new string[0], " Http ")]
    [InlineData(new[] { "--http" }, "stdio")]          // the flag wins over the variable
    [InlineData(new[] { "--http" }, "nonsense")]
    public void Http_mode_needs_the_flag_or_the_variable(string[] args, string? variable)
    {
        Assert.True(StartupOptions.TryParse(args, variable, out var options, out _));
        Assert.Equal(TransportKind.Http, options.Transport);
        Assert.False(options.AllowAnonymous);
        Assert.Empty(options.HostArgs);
    }

    [Fact]
    public void Allow_anonymous_is_off_unless_the_flag_is_given()
    {
        Assert.True(StartupOptions.TryParse(["--http", "--allow-anonymous"], null, out var withFlag, out _));
        Assert.True(withFlag.AllowAnonymous);

        Assert.True(StartupOptions.TryParse(["--http"], null, out var withoutFlag, out _));
        Assert.False(withoutFlag.AllowAnonymous);
    }

    [Fact]
    public void An_unknown_transport_value_is_refused()
    {
        Assert.False(StartupOptions.TryParse([], "sse", out _, out var error));
        Assert.Equal("NO2SQL_TRANSPORT must be 'stdio' or 'http'.", error);
    }

    [Theory]
    [InlineData("--urls=http://0.0.0.0:9999")]
    [InlineData("--allow-anonymus")]
    [InlineData("--Kestrel:Endpoints:Http:Url=http://0.0.0.0:9999")]
    public void Http_mode_refuses_arguments_it_does_not_know_without_repeating_them(string argument)
    {
        Assert.False(StartupOptions.TryParse(["--http", argument], null, out _, out var error));
        Assert.Equal("Unknown argument in HTTP mode. The only arguments are --http and --allow-anonymous.", error);
        Assert.DoesNotContain(argument, error);
    }

    [Fact]
    public void Stdio_mode_passes_its_arguments_through_untouched()
    {
        string[] args = ["--some-host-setting=1", "extra"];

        Assert.True(StartupOptions.TryParse(args, null, out var options, out _));

        Assert.Equal(TransportKind.Stdio, options.Transport);
        Assert.Same(args, options.HostArgs);
    }
}
