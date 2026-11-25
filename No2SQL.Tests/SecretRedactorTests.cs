using No2SQL.Security;

namespace No2SQL.Tests;

/// <summary>P2-7: every secret the process knows is masked in whatever it writes to stdout and stderr.</summary>
public class SecretRedactorTests
{
    [Fact]
    public void A_connection_string_and_its_password_are_masked()
    {
        var redactor = new SecretRedactor();
        redactor.AddConnectionString("mongodb://reader:s3cret-pass@db.example:27017/?authSource=admin");

        Assert.Equal(
            $"connecting with {SecretRedactor.Mask}",
            redactor.Redact("connecting with mongodb://reader:s3cret-pass@db.example:27017/?authSource=admin"));
        Assert.Equal($"auth failed for password {SecretRedactor.Mask}", redactor.Redact("auth failed for password s3cret-pass"));
        Assert.Equal("nothing secret here", redactor.Redact("nothing secret here"));
    }

    [Theory]
    [InlineData("mongodb+srv://u:p%40ss%2Fword@cluster0.example.net/", "p%40ss%2Fword", "p@ss/word")]
    [InlineData("mongodb://u:pa@ss@127.0.0.1:9/", "pa@ss", null)]          // unescaped '@': the last one ends the user info
    [InlineData("mongodb//u:malformed-pw@127.0.0.1:9/", "malformed-pw", null)] // the driver rejects it; the password is still found
    public void The_password_is_found_as_written_and_percent_decoded(string connectionString, string written, string? decoded)
    {
        var redactor = new SecretRedactor();
        redactor.AddConnectionString(connectionString);

        Assert.Equal(SecretRedactor.Mask, redactor.Redact(written));
        if (decoded is not null)
        {
            Assert.Equal(SecretRedactor.Mask, redactor.Redact(decoded));
        }
    }

    [Fact]
    public void A_bare_value_that_is_not_a_URI_is_masked_whole()
    {
        var redactor = new SecretRedactor();
        redactor.AddConnectionString("0123456789abcdef");

        Assert.Equal($"value {SecretRedactor.Mask}.", redactor.Redact("value 0123456789abcdef."));
    }

    [Fact]
    public void The_token_and_owner_password_variables_are_masked()
    {
        var variables = new Dictionary<string, string?>
        {
            ["NO2SQL_HTTP_TOKEN"] = "token-canary-1234",
            ["NO2SQL_OWNER_PASSWORD"] = "owner-canary-5678",
        };
        var redactor = new SecretRedactor();
        redactor.AddSecretVariables(name => variables.GetValueOrDefault(name));

        Assert.Equal(
            $"Bearer {SecretRedactor.Mask} / {SecretRedactor.Mask}",
            redactor.Redact("Bearer token-canary-1234 / owner-canary-5678"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("abc")]
    public void Empty_and_very_short_values_are_not_registered(string? value)
    {
        var redactor = new SecretRedactor();
        redactor.Add(value);

        Assert.Equal("abc def", redactor.Redact("abc def"));
    }

    [Fact]
    public void The_longest_secret_is_replaced_first()
    {
        var redactor = new SecretRedactor();
        redactor.Add("pass");
        redactor.Add("mongodb://u:pass@h/");

        Assert.Equal(SecretRedactor.Mask, redactor.Redact("mongodb://u:pass@h/"));
    }

    [Fact]
    public void The_writer_masks_every_kind_of_write()
    {
        var redactor = new SecretRedactor();
        redactor.Add("writer-secret");
        var inner = new StringWriter();
        var writer = new RedactingTextWriter(inner, redactor);

        writer.Write("a writer-secret ");
        writer.WriteLine("b writer-secret");
        writer.Write("c writer-secret\n".ToCharArray(), 0, 16);
        writer.WriteLine("d writer-secret".AsSpan());
        writer.Write(new InvalidOperationException("e writer-secret"));
        writer.WriteLine();
        writer.WriteAsync("f writer-secret").GetAwaiter().GetResult();
        writer.WriteLineAsync("g writer-secret".AsMemory()).GetAwaiter().GetResult();
        writer.Flush();

        var text = inner.ToString();
        Assert.DoesNotContain("writer-secret", text);
        Assert.Equal(7, text.Split(SecretRedactor.Mask).Length - 1);
    }

    [Fact]
    public void A_secret_added_after_the_writer_was_created_is_masked_too()
    {
        var redactor = new SecretRedactor();
        var inner = new StringWriter();
        var writer = new RedactingTextWriter(inner, redactor);

        redactor.Add("late-secret");
        writer.WriteLine("x late-secret");

        Assert.Equal($"x {SecretRedactor.Mask}{Environment.NewLine}", inner.ToString());
    }
}
