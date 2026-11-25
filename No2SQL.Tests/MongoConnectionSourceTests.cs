using No2SQL.Hosting;
using No2SQL.Security;

namespace No2SQL.Tests;

/// <summary>P2-7: NO2SQL_MONGO_FILE (a Docker or Kubernetes secret) and NO2SQL_MONGO.</summary>
public sealed class MongoConnectionSourceTests : IDisposable
{
    private const string FromVariable = "mongodb://env-user:env-password@env-host:27017/";
    private const string FromFile = "mongodb://file-user:file-password@file-host:27017/";

    private readonly string _directory = Directory.CreateTempSubdirectory("no2sql-tests-").FullName;
    private readonly Dictionary<string, string?> _variables = new();
    private readonly StringWriter _notices = new();
    private readonly SecretRedactor _redactor = new();

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private bool Read(out string? connectionString, out string? error, TimeSpan? fileTimeout = null) =>
        No2SqlServices.TryReadMongoConnectionString(name => _variables.GetValueOrDefault(name), _notices, _redactor, out connectionString, out error, fileTimeout);

    private string MakeFifo()
    {
        var path = Path.Combine(_directory, "pipe");
        using var mkfifo = System.Diagnostics.Process.Start("mkfifo", path);
        mkfifo.WaitForExit();
        Assert.Equal(0, mkfifo.ExitCode);
        return path;
    }

    private string WriteSecretFile(string contents, UnixFileMode mode = UnixFileMode.UserRead | UnixFileMode.UserWrite)
    {
        var path = Path.Combine(_directory, "mongo");
        File.WriteAllText(path, contents);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, mode);
        }

        return path;
    }

    [Fact]
    public void The_variable_is_used_when_there_is_no_file()
    {
        _variables["NO2SQL_MONGO"] = FromVariable;

        Assert.True(Read(out var connectionString, out var error));

        Assert.Null(error);
        Assert.Equal(FromVariable, connectionString);
        Assert.Equal(string.Empty, _notices.ToString());
        Assert.Equal(SecretRedactor.Mask, _redactor.Redact("env-password"));
    }

    [Fact]
    public void Nothing_set_starts_without_a_connection_string_and_says_so()
    {
        Assert.True(Read(out var connectionString, out var error));

        Assert.Null(error);
        Assert.Null(connectionString);
        Assert.Contains("NO2SQL_MONGO is not set", _notices.ToString());
    }

    [Theory]
    [InlineData("\n")]
    [InlineData("\r\n")]
    [InlineData("\n\n")]
    [InlineData("")]
    public void The_file_is_read_and_its_trailing_newline_dropped(string ending)
    {
        _variables["NO2SQL_MONGO_FILE"] = WriteSecretFile(FromFile + ending);

        Assert.True(Read(out var connectionString, out _));

        Assert.Equal(FromFile, connectionString);
        Assert.Equal(string.Empty, _notices.ToString());
        Assert.Equal(SecretRedactor.Mask, _redactor.Redact("file-password"));
    }

    [Fact]
    public void The_file_wins_over_the_variable_and_both_are_masked()
    {
        _variables["NO2SQL_MONGO"] = FromVariable;
        _variables["NO2SQL_MONGO_FILE"] = WriteSecretFile(FromFile + "\n");

        Assert.True(Read(out var connectionString, out _));

        Assert.Equal(FromFile, connectionString);
        Assert.Contains("Both NO2SQL_MONGO_FILE and NO2SQL_MONGO are set; using NO2SQL_MONGO_FILE.", _notices.ToString());
        Assert.Equal($"{SecretRedactor.Mask} {SecretRedactor.Mask}", _redactor.Redact("env-password file-password"));
    }

    [Fact]
    public void A_file_other_users_can_read_gets_a_warning()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "Unix file modes only");
        _variables["NO2SQL_MONGO_FILE"] = WriteSecretFile(FromFile, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);

        Assert.True(Read(out var connectionString, out _));

        Assert.Equal(FromFile, connectionString);
        Assert.Contains("can be read by other users (mode 644)", _notices.ToString());
    }

    [Fact]
    public void A_missing_file_refuses_to_start_without_quoting_anything_secret()
    {
        _variables["NO2SQL_MONGO"] = FromVariable;
        _variables["NO2SQL_MONGO_FILE"] = Path.Combine(_directory, "does-not-exist");

        Assert.False(Read(out var connectionString, out var error));

        Assert.Null(connectionString);
        Assert.Equal($"NO2SQL_MONGO_FILE is set, but {Path.Combine(_directory, "does-not-exist")} could not be read (FileNotFoundException).", error);
        Assert.DoesNotContain("env-password", error);
    }

    [Theory]
    [InlineData("")]
    [InlineData("\n")]
    [InlineData("  \r\n")]
    public void An_empty_file_refuses_to_start(string contents)
    {
        var path = WriteSecretFile(contents);
        _variables["NO2SQL_MONGO_FILE"] = path;

        Assert.False(Read(out _, out var error));

        Assert.Equal($"NO2SQL_MONGO_FILE is set, but {path} is empty.", error);
    }

    [Fact]
    public void An_oversized_file_refuses_to_start_without_quoting_it()
    {
        var path = WriteSecretFile("mongodb://u:oversized-secret@h/" + new string('x', 70 * 1024));
        _variables["NO2SQL_MONGO_FILE"] = path;

        Assert.False(Read(out _, out var error));

        Assert.Equal($"NO2SQL_MONGO_FILE ({path}) is larger than 64 KiB; it should hold only the MongoDB connection string.", error);
    }

    [Fact]
    public void A_named_pipe_with_no_writer_refuses_to_start_instead_of_hanging()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "named pipes as files are Unix only");
        var path = MakeFifo();
        _variables["NO2SQL_MONGO_FILE"] = path;
        var started = DateTime.UtcNow;

        Assert.False(Read(out var connectionString, out var error, TimeSpan.FromMilliseconds(500)));

        Assert.True(DateTime.UtcNow - started < TimeSpan.FromSeconds(3));
        Assert.Null(connectionString);
        Assert.Equal(
            $"NO2SQL_MONGO_FILE is set, but {path} could not be read within 0.5 s. Point it at a regular file (a named pipe with no writer never delivers anything).",
            error);

        // Release the blocked reader so the worker thread ends.
        using var writer = new FileStream(path, FileMode.Open, FileAccess.Write);
    }

    [Fact]
    public void A_named_pipe_with_a_writer_works_like_process_substitution()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "named pipes as files are Unix only");
        var path = MakeFifo();
        _variables["NO2SQL_MONGO_FILE"] = path;
        var writer = Task.Run(() => File.WriteAllText(path, FromFile + "\n"), TestContext.Current.CancellationToken);

        Assert.True(Read(out var connectionString, out var error, TimeSpan.FromSeconds(5)), error);

        Assert.Equal(FromFile, connectionString);
        writer.Wait(TestContext.Current.CancellationToken);
    }

    [Fact]
    public void A_directory_refuses_to_start()
    {
        _variables["NO2SQL_MONGO_FILE"] = _directory;

        Assert.False(Read(out _, out var error));

        Assert.StartsWith($"NO2SQL_MONGO_FILE is set, but {_directory} could not be read (", error);
    }
}
