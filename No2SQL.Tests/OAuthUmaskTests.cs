using System.Runtime.InteropServices;
using No2SQL.Hosting.OAuth;
using No2SQL.Tests.Infrastructure;
using Xunit;

namespace No2SQL.Tests;

/// <summary>The umask belongs to the whole process, so these tests run on their own, after the parallel ones.</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class ProcessUmaskCollection
{
    public const string Name = "Process umask";
}

/// <summary>
/// P2-5 threat model R25: the data directory is 0700 and every file in it 0600 whatever umask the server was
/// started with. A file reaches its name by a rename of the temporary file, so the mode seen here is the mode
/// the temporary file had.
/// </summary>
[Collection(ProcessUmaskCollection.Name)]
public sealed class OAuthUmaskTests
{
    private const UnixFileMode OwnerOnlyDirectory = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode OwnerOnlyFile = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    [DllImport("libc", EntryPoint = "umask")]
    private static extern uint SetUmask(uint mask);

    [Theory]
    [InlineData("000")]   // takes nothing away: a file made with the default mode would be 0666
    [InlineData("022")]
    [InlineData("077")]
    [InlineData("277")]   // takes the owner's write bit away
    [InlineData("777")]   // takes everything away
    public async Task The_directory_is_0700_and_every_file_0600_under_any_umask(string umask)
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "Unix file modes.");

        var previous = SetUmask(Convert.ToUInt32(umask, 8));
        try
        {
            using var server = new BuiltinAuthServer();
            using var generated = new BuiltinAuthServer(ownerPassword: null);   // writes owner-password.json
            _ = generated.Services.GetService(typeof(OwnerCredential));
            var signedIn = await server.SignInAsync();
            Assert.Equal(0, server.Cli("rotate-keys").ExitCode);
            Assert.Equal(0, server.Cli("revoke", signedIn.ClientId).ExitCode);
            await server.SignInAsync();   // every file is rewritten at least once after its creation

            AssertOwnerOnly(server.DataDirectory, umask, ".lock", OAuthDataDirectory.ClientsFile, OAuthDataDirectory.GrantsFile, OAuthDataDirectory.KeysFile);
            AssertOwnerOnly(generated.DataDirectory, umask, ".lock", OAuthDataDirectory.OwnerPasswordFile, OAuthDataDirectory.KeysFile);
        }
        finally
        {
            SetUmask(previous);
        }
    }

    private static void AssertOwnerOnly(string directory, string umask, params string[] expected)
    {
        Assert.Equal(OwnerOnlyDirectory, File.GetUnixFileMode(directory));
        var entries = Directory.GetFileSystemEntries(directory);
        Assert.Equal(expected.Order(StringComparer.Ordinal), entries.Select(Path.GetFileName).Order(StringComparer.Ordinal));
        foreach (var entry in entries)
        {
            Assert.True(File.GetUnixFileMode(entry) == OwnerOnlyFile, $"{Path.GetFileName(entry)} is {File.GetUnixFileMode(entry)} under umask {umask}");
        }
    }
}
