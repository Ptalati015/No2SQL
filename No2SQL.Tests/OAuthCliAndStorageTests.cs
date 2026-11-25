using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.Tokens;
using No2SQL.Hosting;
using No2SQL.Hosting.OAuth;
using No2SQL.Tests.Infrastructure;

namespace No2SQL.Tests;

/// <summary>
/// The data directory and the owner's <c>No2SQL oauth</c> commands (P2-5 threat model R15, R23, R25, R26;
/// tests 16 and 17). The commands run in this process against the running test server's directory, through
/// the same code the command line runs; a second real process is covered by the release checks.
/// </summary>
public sealed class OAuthCliAndStorageTests : IDisposable
{
    private const UnixFileMode OwnerOnlyDirectory = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode OwnerOnlyFile = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    private static CancellationToken Cancel => TestContext.Current.CancellationToken;

    private readonly BuiltinAuthServer _server = new();
    private readonly string _scratch = Path.Combine(Path.GetTempPath(), "no2sql-oauth-cli-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        _server.Dispose();
        try
        {
            if (Directory.Exists(_scratch))
            {
                if (!OperatingSystem.IsWindows())
                {
                    File.SetUnixFileMode(_scratch, OwnerOnlyDirectory);
                }

                Directory.Delete(_scratch, recursive: true);
            }
        }
        catch (IOException)
        {
        }
    }

    private string KeysPath => Path.Combine(_server.DataDirectory, OAuthDataDirectory.KeysFile);

    private JsonArray StoredKeys() => JsonNode.Parse(File.ReadAllText(KeysPath))!["keys"]!.AsArray();

    private async Task<string[]> JwksKidsAsync()
    {
        var jwks = JsonNode.Parse(await _server.Client.GetStringAsync(OAuthServerEndpoints.JwksPath, Cancel))!;
        return [.. jwks["keys"]!.AsArray().Select(k => (string)k!["kid"]!)];
    }

    // A directory prepared the way a first start leaves it, for the start-up checks.
    private (HttpAuthOptions Auth, FakeTimeProvider Clock) FreshDirectory(string? ownerPassword = null) =>
        (new HttpAuthOptions { Builtin = true, PublicUrl = new Uri(BuiltinAuthServer.PublicUrl), DataDirectory = _scratch, OwnerPassword = ownerPassword },
            new FakeTimeProvider(new DateTimeOffset(2026, 11, 25, 12, 0, 0, TimeSpan.Zero)));

    private static string? Prepare((HttpAuthOptions Auth, FakeTimeProvider Clock) setup, out OwnerCredential? credential, out string? generated, out List<string> warnings) =>
        OAuthServerSetup.Prepare(setup.Auth, setup.Clock, out _, out credential, out generated, out warnings);

    private static string? Prepare((HttpAuthOptions Auth, FakeTimeProvider Clock) setup) => Prepare(setup, out _, out _, out _);

    // ---- R23: revoke-all, revoke, rotate-keys and list against a running server ----

    [Fact]
    public async Task Revoke_all_stops_every_access_and_refresh_token_within_a_second_without_a_restart()
    {
        var signedIn = await _server.SignInAsync();
        var neverApproved = await _server.RegisterAsync("https://unused.example.test/callback");
        var oldKid = _server.ActiveKid();
        Assert.Equal(HttpStatusCode.OK, await _server.McpStatusAsync(signedIn.AccessToken));

        var (exitCode, output, error) = _server.Cli("revoke-all");

        Assert.Equal(0, exitCode);
        Assert.Equal("", error);
        Assert.Contains("1 grant(s) deleted, 1 never-approved client(s) deleted", output);
        _server.Clock.Advance(TimeSpan.FromSeconds(1));
        Assert.Equal(HttpStatusCode.Unauthorized, await _server.McpStatusAsync(signedIn.AccessToken));
        Assert.Equal(HttpStatusCode.BadRequest, (await _server.RefreshAsync(signedIn.RefreshToken, signedIn.ClientId)).Status);

        // The key set is one new active key and no retiring key, and the JWKS shows only that key.
        var key = Assert.Single(StoredKeys())!;
        Assert.Equal("active", (string)key["status"]!);
        Assert.Null(key["retire_at"]);
        Assert.NotEqual(oldKid, (string)key["kid"]!);
        Assert.Contains($"new signing key {(string)key["kid"]!}", output);
        Assert.Equal(new[] { (string)key["kid"]! }, await JwksKidsAsync());

        // The never-approved client is gone; the approved one is still registered and can sign in again.
        using var gone = await _server.AuthorizeAsync(BuiltinAuthServer.AuthorizeParameters(neverApproved, "https://unused.example.test/callback", BuiltinAuthServer.NewPkce().Challenge));
        Assert.Equal(HttpStatusCode.BadRequest, gone.StatusCode);
        var again = await _server.SignInAsync(signedIn.ClientId);
        Assert.Equal(HttpStatusCode.OK, await _server.McpStatusAsync(again.AccessToken));
        Assert.Equal((string)key["kid"]!, (string)BuiltinAuthServer.Decode(again.AccessToken).Header["kid"]!);
    }

    [Fact]
    public async Task Rotate_keys_keeps_old_tokens_working_until_they_expire_and_signs_new_ones_with_the_new_key()
    {
        var before = await _server.SignInAsync();
        var oldKid = _server.ActiveKid();
        var rotatedAt = _server.Clock.GetUtcNow();

        var (exitCode, output, error) = _server.Cli("rotate-keys");

        var newKid = _server.ActiveKid();
        Assert.Equal(0, exitCode);
        Assert.Equal("", error);
        Assert.NotEqual(oldKid, newKid);
        Assert.Equal($"New signing key {newKid}. The previous key {oldKid} keeps validating tokens until 2026-11-25 13:01 UTC.", output.Trim());

        // The file: the old key is retiring until now + access-token lifetime + 60 s.
        var keys = StoredKeys();
        Assert.Equal(2, keys.Count);
        var retiring = keys.Single(k => (string?)k!["status"] == "retiring")!;
        Assert.Equal(oldKid, (string)retiring["kid"]!);
        Assert.Equal(rotatedAt + TimeSpan.FromMinutes(61), retiring["retire_at"]!.GetValue<DateTimeOffset>());

        _server.Clock.Advance(TimeSpan.FromSeconds(1));
        Assert.Equal(HttpStatusCode.OK, await _server.McpStatusAsync(before.AccessToken));
        Assert.Equal(new[] { newKid, oldKid }, await JwksKidsAsync());
        var (_, refreshed) = await _server.RefreshAsync(before.RefreshToken, before.ClientId);
        var newAccessToken = (string)refreshed!["access_token"]!;
        Assert.Equal(newKid, (string)BuiltinAuthServer.Decode(newAccessToken).Header["kid"]!);
        Assert.Equal(HttpStatusCode.OK, await _server.McpStatusAsync(newAccessToken));

        // Until its exp (and the skew) the old token keeps working.
        _server.Clock.Advance(TimeSpan.FromMinutes(60));
        Assert.Equal(HttpStatusCode.OK, await _server.McpStatusAsync(before.AccessToken));

        // After retire_at the old key validates nothing, even a token that says it has not expired, and has left the JWKS.
        _server.Clock.Advance(TimeSpan.FromMinutes(1));
        var forged = _server.SignWithKey(new JsonObject { ["alg"] = "ES256", ["typ"] = "at+jwt" }, _server.GoodPayload(), oldKid);
        Assert.Equal(HttpStatusCode.Unauthorized, await _server.McpStatusAsync(forged));
        Assert.Equal(new[] { newKid }, await JwksKidsAsync());
    }

    [Fact]
    public async Task A_second_rotation_keeps_a_key_that_is_still_retiring_and_drops_one_that_has_retired()
    {
        var first = _server.ActiveKid();
        _server.Cli("rotate-keys");
        var second = _server.ActiveKid();
        _server.Clock.Advance(TimeSpan.FromMinutes(30));
        _server.Cli("rotate-keys");
        var third = _server.ActiveKid();

        Assert.Equal(new[] { third, second, first }, StoredKeys().Select(k => (string)k!["kid"]!));
        Assert.Equal(new[] { "active", "retiring", "retiring" }, StoredKeys().Select(k => (string)k!["status"]!));

        _server.Clock.Advance(TimeSpan.FromMinutes(31));   // the first key retired after 61 minutes
        _server.Cli("rotate-keys");

        Assert.DoesNotContain(first, StoredKeys().Select(k => (string)k!["kid"]!));
        Assert.Equal(3, StoredKeys().Count);
        Assert.Single(StoredKeys(), k => (string?)k!["status"] == "active");
    }

    [Fact]
    public void Rotate_keys_uses_the_configured_access_token_lifetime_for_the_grace_period()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        string? Variables(string name) => name switch
        {
            HttpAuthOptions.DataDirectoryVariable => _server.DataDirectory,
            HttpAuthOptions.AccessTokenMinutesVariable => "5",
            _ => null,
        };

        var exitCode = OAuthCli.Run(["rotate-keys"], Variables, _server.Clock, output, error);

        Assert.Equal(0, exitCode);
        var retiring = StoredKeys().Single(k => (string?)k!["status"] == "retiring")!;
        Assert.Equal(_server.Clock.GetUtcNow() + TimeSpan.FromMinutes(6), retiring["retire_at"]!.GetValue<DateTimeOffset>());

        var badExitCode = OAuthCli.Run(["rotate-keys"], name => name == HttpAuthOptions.AccessTokenMinutesVariable ? "soon" : Variables(name), _server.Clock, output, error);
        Assert.Equal(2, badExitCode);
        Assert.Contains("NO2SQL_OAUTH_ACCESS_TOKEN_MINUTES must be a whole number of minutes from 5 to 1440.", error.ToString());
        Assert.Equal(2, StoredKeys().Count);   // nothing was rotated
    }

    [Fact]
    public async Task Revoke_cuts_off_one_client_within_a_second_and_leaves_the_others()
    {
        var first = await _server.SignInAsync();
        var second = await _server.SignInAsync();

        var (exitCode, output, error) = _server.Cli("revoke", first.ClientId);

        Assert.Equal(0, exitCode);
        Assert.Equal("", error);
        Assert.StartsWith($"Revoked {first.ClientId}: 1 grant(s) deleted, its access tokens refused, approval forgotten.", output);
        _server.Clock.Advance(TimeSpan.FromSeconds(1));
        Assert.Equal(HttpStatusCode.Unauthorized, await _server.McpStatusAsync(first.AccessToken));
        Assert.Equal(HttpStatusCode.BadRequest, (await _server.RefreshAsync(first.RefreshToken, first.ClientId)).Status);
        Assert.Equal(HttpStatusCode.OK, await _server.McpStatusAsync(second.AccessToken));
        Assert.Equal(HttpStatusCode.OK, (await _server.RefreshAsync(second.RefreshToken, second.ClientId)).Status);

        var (unknownExitCode, _, unknownError) = _server.Cli("revoke", "no-such-client");
        Assert.Equal(1, unknownExitCode);
        Assert.Contains("No client no-such-client has an approval or a grant.", unknownError);
    }

    [Fact]
    public async Task List_shows_clients_approvals_grants_and_key_ids_and_nothing_secret()
    {
        var signedIn = await _server.SignInAsync();
        var pending = await _server.RegisterAsync("http://127.0.0.1:8123/callback", name: "Local tool");
        var oldKid = _server.ActiveKid();
        _server.Cli("rotate-keys");

        var (exitCode, output, error) = _server.Cli("list");

        Assert.Equal(0, exitCode);
        Assert.Equal("", error);
        Assert.Contains($"Data directory: {_server.DataDirectory}", output);
        Assert.Contains($"  {signedIn.ClientId}  \"Test client\"  redirects to client.example.test; registered 2026-11-25 12:00 UTC, approved 2026-11-25 12:00 UTC; 1 live grant(s)", output);
        Assert.Contains($"  {pending}  \"Local tool\"  redirects to an app on your computer; registered 2026-11-25 12:00 UTC, never approved; 0 live grant(s)", output);
        Assert.Contains($"  {_server.ActiveKid()}  active", output);
        Assert.Contains($"  {oldKid}  retiring until 2026-11-25 13:01 UTC", output);

        Assert.DoesNotContain(signedIn.RefreshToken, output);
        Assert.DoesNotContain(GrantStore.Hash(signedIn.RefreshToken), output);
        foreach (var key in StoredKeys())
        {
            Assert.DoesNotContain((string)key!["d"]!, output);
        }
    }

    [Fact]
    public void Wrong_usage_exits_2_and_help_exits_0()
    {
        Assert.Equal(2, _server.Cli().ExitCode);
        Assert.Contains("Usage: No2SQL oauth <command>", _server.Cli().Error);
        Assert.Equal(0, _server.Cli("--help").ExitCode);
        Assert.Contains("revoke-all", _server.Cli("--help").Output);
        Assert.Equal(2, _server.Cli("revoke").ExitCode);
        Assert.Equal(2, _server.Cli("list", "extra").ExitCode);
        Assert.Equal(2, _server.Cli("delete-everything").ExitCode);
        Assert.Single(StoredKeys());   // nothing was changed
    }

    [Theory]
    [InlineData("list")]
    [InlineData("revoke-all")]
    [InlineData("rotate-keys")]
    public void A_missing_data_directory_is_reported_with_its_path_and_not_created(string command)
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = OAuthCli.Run([command], name => name == HttpAuthOptions.DataDirectoryVariable ? _scratch : null, _server.Clock, output, error);

        Assert.Equal(1, exitCode);
        Assert.Contains($"There is no data directory at {_scratch}.", error.ToString());
        Assert.False(Directory.Exists(_scratch));
    }

    [Fact]
    public void A_relative_data_directory_is_refused()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = OAuthCli.Run(["list"], name => name == HttpAuthOptions.DataDirectoryVariable ? "data" : null, _server.Clock, output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("NO2SQL_DATA_DIR must be an absolute path.", error.ToString());
    }

    [Fact]
    public void A_file_that_cannot_be_replaced_is_reported_with_the_directory_and_leaves_no_temporary_file()
    {
        // A directory where refresh-tokens.json should be: the rename over it fails for any user, root included.
        Directory.CreateDirectory(Path.Combine(_server.DataDirectory, OAuthDataDirectory.GrantsFile));

        var (exitCode, _, error) = _server.Cli("revoke-all");

        Assert.Equal(1, exitCode);
        Assert.Contains(_server.DataDirectory, error);
        Assert.DoesNotContain(Directory.GetFiles(_server.DataDirectory), file => file.EndsWith(".tmp", StringComparison.Ordinal));
    }

    [Fact]
    public void A_data_directory_the_user_cannot_write_is_refused_with_its_path()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows() || Environment.IsPrivilegedProcess, "File modes do not stop this user.");
        var before = File.ReadAllText(KeysPath);
        File.SetUnixFileMode(_server.DataDirectory, UnixFileMode.UserRead | UnixFileMode.UserExecute);
        try
        {
            var (exitCode, _, error) = _server.Cli("rotate-keys");

            Assert.Equal(1, exitCode);
            Assert.Contains($"Cannot write to {_server.DataDirectory}", error);
            Assert.Equal(before, File.ReadAllText(KeysPath));
        }
        finally
        {
            File.SetUnixFileMode(_server.DataDirectory, OwnerOnlyDirectory);
        }
    }

    // ---- Fail closed while a file is damaged ----

    [Fact]
    public async Task A_damaged_refresh_token_file_refuses_every_access_token_until_it_can_be_read_again()
    {
        var signedIn = await _server.SignInAsync();
        var path = Path.Combine(_server.DataDirectory, OAuthDataDirectory.GrantsFile);
        var good = File.ReadAllText(path);

        File.WriteAllText(path, "{ damaged");
        _server.Clock.Advance(TimeSpan.FromSeconds(1));

        Assert.Equal(HttpStatusCode.Unauthorized, await _server.McpStatusAsync(signedIn.AccessToken));
        Assert.Equal(HttpStatusCode.Unauthorized, await _server.McpStatusAsync(signedIn.AccessToken));   // not answered from the cached copy
        var (status, body) = await _server.RefreshAsync(signedIn.RefreshToken, signedIn.ClientId);
        Assert.Equal(HttpStatusCode.InternalServerError, status);
        Assert.Equal("server_error", (string)body!["error"]!);
        Assert.Contains(_server.Logs.Lines, line => line.Contains("every access token is refused") && line.Contains(path));

        File.WriteAllText(path, good);
        _server.Clock.Advance(TimeSpan.FromSeconds(1));
        Assert.Equal(HttpStatusCode.OK, await _server.McpStatusAsync(signedIn.AccessToken));
    }

    [Fact]
    public async Task A_damaged_key_file_refuses_every_access_token_and_issues_none_until_it_can_be_read_again()
    {
        var signedIn = await _server.SignInAsync();
        var good = File.ReadAllText(KeysPath);

        File.WriteAllText(KeysPath, """{"keys":[]}""");
        _server.Clock.Advance(TimeSpan.FromSeconds(1));

        Assert.Equal(HttpStatusCode.Unauthorized, await _server.McpStatusAsync(signedIn.AccessToken));
        Assert.Empty(await JwksKidsAsync());
        var (status, body) = await _server.RefreshAsync(signedIn.RefreshToken, signedIn.ClientId);
        Assert.Equal(HttpStatusCode.InternalServerError, status);
        Assert.Equal("""{"error":"server_error","error_description":"The server could not complete the request."}""", body!.ToJsonString());
        Assert.Contains(_server.Logs.Lines, line => line.Contains("The signing keys could not be reloaded"));

        File.WriteAllText(KeysPath, good);
        _server.Clock.Advance(TimeSpan.FromSeconds(1));
        Assert.Equal(HttpStatusCode.OK, await _server.McpStatusAsync(signedIn.AccessToken));
    }

    // ---- R25: permissions (test 16) ----

    [Fact]
    public async Task The_data_directory_is_0700_and_every_file_in_it_0600()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "Unix file modes.");
        using var generated = new BuiltinAuthServer(ownerPassword: null);
        _ = generated.Services.GetService(typeof(OwnerCredential));
        var signedIn = await _server.SignInAsync();
        _server.Cli("rotate-keys");
        _server.Cli("revoke", signedIn.ClientId);

        foreach (var directory in new[] { _server.DataDirectory, generated.DataDirectory })
        {
            Assert.Equal(OwnerOnlyDirectory, File.GetUnixFileMode(directory));
            foreach (var file in Directory.GetFiles(directory))
            {
                Assert.True(File.GetUnixFileMode(file) == OwnerOnlyFile, $"{Path.GetFileName(file)} is {File.GetUnixFileMode(file)}");
            }
        }

        Assert.Equal(
            new[] { ".lock", OAuthDataDirectory.ClientsFile, OAuthDataDirectory.GrantsFile, OAuthDataDirectory.KeysFile },
            Directory.GetFiles(_server.DataDirectory).Select(Path.GetFileName).Order(StringComparer.Ordinal));
        Assert.Contains(Path.Combine(generated.DataDirectory, OAuthDataDirectory.OwnerPasswordFile), Directory.GetFiles(generated.DataDirectory));
    }

    [Fact]
    public void Start_up_creates_the_directory_owner_only_and_warns_about_looser_modes()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "Unix file modes.");
        var setup = FreshDirectory();

        Assert.Null(Prepare(setup, out _, out _, out var firstWarnings));
        Assert.Empty(firstWarnings);
        Assert.Equal(OwnerOnlyDirectory, File.GetUnixFileMode(_scratch));
        Assert.Equal(OwnerOnlyFile, File.GetUnixFileMode(Path.Combine(_scratch, OAuthDataDirectory.KeysFile)));
        Assert.Equal(OwnerOnlyFile, File.GetUnixFileMode(Path.Combine(_scratch, OAuthDataDirectory.OwnerPasswordFile)));

        File.SetUnixFileMode(_scratch, OwnerOnlyDirectory | UnixFileMode.GroupRead | UnixFileMode.GroupExecute);
        File.SetUnixFileMode(Path.Combine(_scratch, OAuthDataDirectory.KeysFile), OwnerOnlyFile | UnixFileMode.GroupRead);
        File.SetUnixFileMode(Path.Combine(_scratch, OAuthDataDirectory.OwnerPasswordFile), OwnerOnlyFile | UnixFileMode.OtherRead);

        Assert.Null(Prepare(setup, out _, out _, out var warnings));
        Assert.Equal(3, warnings.Count);
        Assert.Contains(warnings, w => w == $"The data directory {_scratch} can be accessed by other users. Run: chmod 700 '{_scratch}'");
        Assert.Contains(warnings, w => w.Contains(OAuthDataDirectory.KeysFile) && w.Contains("chmod 600"));
        Assert.Contains(warnings, w => w.Contains(OAuthDataDirectory.OwnerPasswordFile) && w.Contains("chmod 600"));
    }

    [Fact]
    public void Start_up_refuses_a_signing_key_file_that_every_user_can_read()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "Unix file modes.");
        var setup = FreshDirectory();
        Assert.Null(Prepare(setup));
        var keyFile = Path.Combine(_scratch, OAuthDataDirectory.KeysFile);
        File.SetUnixFileMode(keyFile, OwnerOnlyFile | UnixFileMode.GroupRead | UnixFileMode.OtherRead);

        var refusal = Prepare(setup);

        Assert.Equal($"The signing key file {keyFile} is readable by every user on this machine. Run: chmod 600 '{keyFile}', then run 'No2SQL oauth revoke-all' because the key may have been copied.", refusal);
    }

    [Fact]
    public void Start_up_says_so_when_the_data_directory_cannot_be_created()
    {
        Directory.CreateDirectory(_scratch);
        var inTheWay = Path.Combine(_scratch, "a-file");
        File.WriteAllText(inTheWay, "");
        var setup = (new HttpAuthOptions { Builtin = true, PublicUrl = new Uri(BuiltinAuthServer.PublicUrl), DataDirectory = Path.Combine(inTheWay, "data") }, new FakeTimeProvider());

        var refusal = Prepare(setup);

        Assert.StartsWith($"Cannot create the data directory {Path.Combine(inTheWay, "data")} (", refusal);
        Assert.EndsWith("Set NO2SQL_DATA_DIR to a directory No2SQL can write.", refusal);
    }

    [Fact]
    public void Start_up_refuses_a_data_directory_it_cannot_write_even_when_every_file_is_already_there()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows() || Environment.IsPrivilegedProcess, "File modes do not stop this user.");
        var setup = FreshDirectory("Configured-Password-93");
        Assert.Null(Prepare(setup));   // the keys exist and the password is configured: this start writes nothing it needs
        var before = Directory.GetFileSystemEntries(_scratch).Order(StringComparer.Ordinal).ToList();
        File.SetUnixFileMode(_scratch, UnixFileMode.UserRead | UnixFileMode.UserExecute);

        var refusal = Prepare(setup);

        Assert.Equal($"Cannot write to the data directory {_scratch} (UnauthorizedAccessException). Set NO2SQL_DATA_DIR to a directory the user running No2SQL can write.", refusal);
        Assert.Equal(before, Directory.GetFileSystemEntries(_scratch).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void The_start_up_write_check_leaves_nothing_behind()
    {
        var setup = FreshDirectory("Configured-Password-93");

        Assert.Null(Prepare(setup));
        Assert.Null(Prepare(setup));

        Assert.Equal(
            new[] { ".lock", OAuthDataDirectory.KeysFile },
            Directory.GetFileSystemEntries(_scratch).Select(Path.GetFileName).Order(StringComparer.Ordinal));
    }

    // ---- R15: the generated owner password ----

    [Fact]
    public void Without_a_configured_password_one_is_generated_once_and_only_its_hash_is_stored()
    {
        var setup = FreshDirectory();

        Assert.Null(Prepare(setup, out var credential, out var generated, out _));

        Assert.NotNull(generated);
        Assert.Matches("^[A-Za-z0-9]{24}$", generated);
        Assert.True(credential!.Verify(generated));
        Assert.False(credential.Verify(generated + "x"));
        Assert.False(credential.Verify(null));
        var stored = File.ReadAllText(Path.Combine(_scratch, OAuthDataDirectory.OwnerPasswordFile));
        var document = JsonNode.Parse(stored)!;
        Assert.Equal(new[] { "created_at", "sha256" }, document.AsObject().Select(p => p.Key).Order(StringComparer.Ordinal));
        Assert.Equal(Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(generated))), (string)document["sha256"]!);
        Assert.All(Directory.GetFiles(_scratch), file => Assert.DoesNotContain(generated, File.ReadAllText(file)));

        // The notice shows it exactly once; the next start prints nothing and still accepts it.
        var notice = OwnerCredential.GeneratedNotice(generated, new OAuthDataDirectory(_scratch));
        Assert.Equal(2, notice.Split(generated).Length);
        Assert.Null(Prepare(setup, out var again, out var generatedAgain, out _));
        Assert.Null(generatedAgain);
        Assert.True(again!.Verify(generated));
        Assert.DoesNotContain(generated, again.ToString());
    }

    [Fact]
    public void Generated_passwords_differ_and_use_the_whole_62_symbol_alphabet()
    {
        var seen = new HashSet<char>();
        var passwords = new HashSet<string>();
        for (var i = 0; i < 40; i++)
        {
            var directory = new OAuthDataDirectory(Path.Combine(_scratch, i.ToString()));
            directory.EnsureExists();
            var (_, generated) = OwnerCredential.Resolve(null, directory, TimeProvider.System);
            passwords.Add(generated!);
            seen.UnionWith(generated!);
        }

        Assert.Equal(40, passwords.Count);
        Assert.Equal(62, seen.Count);   // 960 draws: missing one of 62 symbols has a chance below 1 in 100,000
        Assert.All(seen, c => Assert.True(char.IsAsciiLetterOrDigit(c)));
    }

    [Fact]
    public void A_configured_password_wins_over_a_stored_one_and_is_never_written()
    {
        var generatedSetup = FreshDirectory();
        Assert.Null(Prepare(generatedSetup, out _, out var generated, out _));
        const string configured = "Configured-Password-93";

        Assert.Null(Prepare(FreshDirectory(configured), out var credential, out var generatedNow, out _));

        Assert.Null(generatedNow);
        Assert.True(credential!.Verify(configured));
        Assert.False(credential.Verify(generated));
        Assert.All(Directory.GetFiles(_scratch), file => Assert.DoesNotContain(configured, File.ReadAllText(file)));
    }

    [Fact]
    public void A_configured_password_alone_writes_no_password_file()
    {
        Assert.Null(Prepare(FreshDirectory("Configured-Password-93")));

        Assert.False(File.Exists(Path.Combine(_scratch, OAuthDataDirectory.OwnerPasswordFile)));
    }

    [Theory]
    [InlineData("""{"sha256":"not base64url!","created_at":"2026-11-25T12:00:00+00:00"}""")]
    [InlineData("""{"sha256":"c2hvcnQ","created_at":"2026-11-25T12:00:00+00:00"}""")]
    [InlineData("{ damaged")]
    public void A_damaged_password_file_refuses_to_start(string content)
    {
        var setup = FreshDirectory();
        Assert.Null(Prepare(setup));
        var path = Path.Combine(_scratch, OAuthDataDirectory.OwnerPasswordFile);
        File.WriteAllText(path, content);

        var refusal = Prepare(setup, out _, out var generated, out _);

        Assert.StartsWith(path, refusal);
        Assert.Null(generated);
        Assert.Equal(content, File.ReadAllText(path));
    }

    // ---- R26: a key file that cannot be used refuses to start and is never replaced silently ----

    [Theory]
    [InlineData("not json")]
    [InlineData("empty file")]
    [InlineData("no keys")]
    [InlineData("two active keys")]
    [InlineData("no active key")]
    [InlineData("no status")]
    [InlineData("another curve")]
    [InlineData("another algorithm")]
    [InlineData("no private key")]
    [InlineData("private key that is not base64url")]
    [InlineData("point not on the curve")]
    [InlineData("retiring without retire_at")]
    [InlineData("no kid")]
    public void An_unusable_key_file_refuses_to_start_and_is_left_as_it_is(string damage)
    {
        var setup = FreshDirectory();
        Assert.Null(Prepare(setup));
        var path = Path.Combine(_scratch, OAuthDataDirectory.KeysFile);
        var document = JsonNode.Parse(File.ReadAllText(path))!;
        var key = document["keys"]![0]!.AsObject();
        string content;
        switch (damage)
        {
            case "not json": content = "{ \"keys\": ["; break;
            case "empty file": content = ""; break;
            case "no keys": content = """{"keys":[]}"""; break;
            case "two active keys": document["keys"]!.AsArray().Add(JsonNode.Parse(JsonNode.Parse(File.ReadAllText(Path.Combine(_server.DataDirectory, OAuthDataDirectory.KeysFile)))!["keys"]![0]!.ToJsonString())); content = document.ToJsonString(); break;
            case "no active key": key["status"] = "retiring"; key["retire_at"] = "2027-01-01T00:00:00+00:00"; content = document.ToJsonString(); break;
            case "no status": key.Remove("status"); content = document.ToJsonString(); break;
            case "another curve": key["crv"] = "P-384"; content = document.ToJsonString(); break;
            case "another algorithm": key["alg"] = "ES384"; content = document.ToJsonString(); break;
            case "no private key": key.Remove("d"); content = document.ToJsonString(); break;
            case "private key that is not base64url": key["d"] = "!!!"; content = document.ToJsonString(); break;
            case "point not on the curve": key["x"] = Base64UrlEncoder.Encode(new byte[31]); content = document.ToJsonString(); break;
            case "retiring without retire_at":
                var second = JsonNode.Parse(JsonNode.Parse(File.ReadAllText(Path.Combine(_server.DataDirectory, OAuthDataDirectory.KeysFile)))!["keys"]![0]!.ToJsonString())!;
                second["status"] = "retiring";
                document["keys"]!.AsArray().Add(second);
                content = document.ToJsonString();
                break;
            case "no kid": key.Remove("kid"); content = document.ToJsonString(); break;
            default: throw new ArgumentOutOfRangeException(nameof(damage));
        }

        File.WriteAllText(path, content);

        var refusal = Prepare(setup);

        Assert.NotNull(refusal);
        Assert.StartsWith(path, refusal);
        Assert.Equal(content, File.ReadAllText(path));
        if (key["d"] is { } d)
        {
            Assert.DoesNotContain((string)d!, refusal);
        }
    }

    [Theory]
    [InlineData(OAuthDataDirectory.ClientsFile)]
    [InlineData(OAuthDataDirectory.GrantsFile)]
    public void An_unparseable_client_or_refresh_token_file_refuses_to_start(string name)
    {
        var setup = FreshDirectory();
        Assert.Null(Prepare(setup));
        var path = Path.Combine(_scratch, name);
        File.WriteAllText(path, "[1, 2");

        Assert.Equal($"{path} is not valid JSON for No2SQL.", Prepare(setup));
    }

    [Fact]
    public async Task Writes_are_atomic_and_concurrent_registrations_lose_nothing()
    {
        var registrations = Enumerable.Range(0, 40).Select(i => _server.RegisterAsync($"https://client-{i}.example.test/callback", ip: $"198.51.100.{i}"));

        var clientIds = await Task.WhenAll(registrations);

        var stored = JsonNode.Parse(File.ReadAllText(Path.Combine(_server.DataDirectory, OAuthDataDirectory.ClientsFile)))!["clients"]!.AsArray();
        Assert.Equal(clientIds.Order(StringComparer.Ordinal), stored.Select(c => (string)c!["client_id"]!).Order(StringComparer.Ordinal));
        Assert.DoesNotContain(Directory.GetFiles(_server.DataDirectory), file => file.EndsWith(".tmp", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Sessions_and_form_tokens_use_no_Data_Protection_key_ring()
    {
        // Sessions and anti-forgery tokens are random values held in memory, so nothing is written outside the
        // data directory (the container image has a read-only file system apart from it).
        var keyRing = new RecordingKeyRing();
        using var server = new BuiltinAuthServer(services =>
            services.Configure<Microsoft.AspNetCore.DataProtection.KeyManagement.KeyManagementOptions>(options => options.XmlRepository = keyRing));

        var signedIn = await server.SignInAsync();
        await server.RefreshAsync(signedIn.RefreshToken, signedIn.ClientId);
        await server.McpStatusAsync(signedIn.AccessToken);
        server.Cli("rotate-keys");

        Assert.Equal(0, keyRing.Calls);
        Assert.Null(server.Services.GetService<Microsoft.AspNetCore.DataProtection.IDataProtectionProvider>());
    }

    private sealed class RecordingKeyRing : Microsoft.AspNetCore.DataProtection.Repositories.IXmlRepository
    {
        private readonly List<System.Xml.Linq.XElement> _elements = [];

        public int Calls;

        public IReadOnlyCollection<System.Xml.Linq.XElement> GetAllElements()
        {
            Interlocked.Increment(ref Calls);
            lock (_elements)
            {
                return [.. _elements];
            }
        }

        public void StoreElement(System.Xml.Linq.XElement element, string friendlyName)
        {
            Interlocked.Increment(ref Calls);
            lock (_elements)
            {
                _elements.Add(element);
            }
        }
    }

    [Fact]
    public async Task A_restart_keeps_the_keys_the_clients_and_the_refresh_tokens()
    {
        var signedIn = await _server.SignInAsync();
        var kid = _server.ActiveKid();
        Directory.CreateDirectory(_scratch);
        foreach (var file in Directory.GetFiles(_server.DataDirectory))
        {
            File.Copy(file, Path.Combine(_scratch, Path.GetFileName(file)));
        }

        // A second server on a copy of the directory stands for the same server after a restart.
        var auth = new HttpAuthOptions
        {
            Builtin = true,
            PublicUrl = new Uri(BuiltinAuthServer.PublicUrl),
            DataDirectory = _scratch,
            OwnerPassword = _server.Password,
            AccessTokenLifetime = TimeSpan.FromMinutes(60),
        };
        using var restarted = new No2SqlHttpApp(services => services.AddSingleton<TimeProvider>(_server.Clock), auth: auth);
        using var client = restarted.CreateClient();

        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = signedIn.RefreshToken,
            ["client_id"] = signedIn.ClientId,
        });
        using var response = await client.PostAsync(OAuthServerEndpoints.TokenPath, form, Cancel);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(Cancel))!;

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(kid, (string)BuiltinAuthServer.Decode((string)body["access_token"]!).Header["kid"]!);
        var reply = await client.RpcAsync("tools/list", configure: request => request.Headers.Authorization = new("Bearer", signedIn.AccessToken), cancellationToken: Cancel);
        Assert.Equal(HttpStatusCode.OK, reply.Http.StatusCode);
    }
}
