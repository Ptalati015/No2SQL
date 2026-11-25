using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;

namespace No2SQL.Hosting.OAuth;

/// <summary>
/// The built-in authorization server's data directory (<c>NO2SQL_DATA_DIR</c>): the signing keys, the
/// client registrations and the refresh-token hashes (threat model R25, R26).
/// <list type="bullet">
/// <item>The directory is created owner-only (0700, or a protected DACL for the current user on Windows),
/// and every file is written owner-only (0600) through a temporary file and a rename, so a crash leaves
/// either the old or the new file.</item>
/// <item>The server and the <c>No2SQL oauth</c> commands change the same files, so every
/// read-modify-write holds an exclusive lock on <c>.lock</c> in the directory.</item>
/// </list>
/// </summary>
internal sealed class OAuthDataDirectory
{
    public const string KeysFile = "signing-keys.json";
    public const string ClientsFile = "clients.json";
    public const string GrantsFile = "refresh-tokens.json";
    public const string OwnerPasswordFile = "owner-password.json";
    private const string LockFile = ".lock";

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    private static readonly TimeSpan LockTimeout = TimeSpan.FromSeconds(10);

    // Serialises lock holders inside one process; the file lock serialises processes.
    private readonly SemaphoreSlim _processLock = new(1, 1);

    public OAuthDataDirectory(string path)
    {
        Path = System.IO.Path.GetFullPath(path);
    }

    /// <summary>The absolute path of the directory.</summary>
    public string Path { get; }

    public string File(string name) => System.IO.Path.Combine(Path, name);

    /// <summary>Creates the directory owner-only if it does not exist.</summary>
    /// <exception cref="IOException">The directory cannot be created.</exception>
    public void EnsureExists()
    {
        if (Directory.Exists(Path))
        {
            return;
        }

        if (OperatingSystem.IsWindows())
        {
            new DirectoryInfo(Path).Create(OwnerOnlyDirectorySecurity());
        }
        else
        {
            Directory.CreateDirectory(Path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

            // CreateDirectory applies the umask; set the mode explicitly so it is exactly 0700.
            System.IO.File.SetUnixFileMode(Path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    /// <summary>
    /// Problems with the permissions of the directory and the key file: warnings to log, and a refusal
    /// when the private key is readable by every local user. Windows ACLs are not inspected.
    /// </summary>
    public (List<string> Warnings, string? Refusal) CheckPermissions()
    {
        var warnings = new List<string>();
        if (OperatingSystem.IsWindows() || !Directory.Exists(Path))
        {
            return (warnings, null);
        }

        const UnixFileMode groupOrOther = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute
            | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;

        if ((System.IO.File.GetUnixFileMode(Path) & groupOrOther) != 0)
        {
            warnings.Add($"The data directory {Path} can be accessed by other users. Run: chmod 700 '{Path}'");
        }

        foreach (var name in new[] { KeysFile, ClientsFile, GrantsFile, OwnerPasswordFile })
        {
            var file = File(name);
            if (!System.IO.File.Exists(file))
            {
                continue;
            }

            var mode = System.IO.File.GetUnixFileMode(file);
            if (name == KeysFile && (mode & UnixFileMode.OtherRead) != 0)
            {
                return (warnings, $"The signing key file {file} is readable by every user on this machine. Run: chmod 600 '{file}', then run 'No2SQL oauth revoke-all' because the key may have been copied.");
            }

            if ((mode & groupOrOther) != 0)
            {
                warnings.Add($"{file} can be read or changed by other users. Run: chmod 600 '{file}'");
            }
        }

        return (warnings, null);
    }

    /// <summary>Last write time and length of a file, or null when it does not exist. Used to notice changes made by another process.</summary>
    public (DateTime, long)? Stamp(string name)
    {
        var info = new FileInfo(File(name));
        return info.Exists ? (info.LastWriteTimeUtc, info.Length) : null;
    }

    /// <summary>Reads a JSON file, or returns null when it does not exist.</summary>
    /// <exception cref="OAuthDataException">The file exists but cannot be read or parsed.</exception>
    public T? Read<T>(string name) where T : class
    {
        var path = File(name);
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return JsonSerializer.Deserialize<T>(stream, Json) ?? throw new OAuthDataException($"{path} is empty.");
        }
        catch (FileNotFoundException)
        {
            return null;
        }
        catch (DirectoryNotFoundException)
        {
            return null;
        }
        catch (Exception ex) when (ex is JsonException or NotSupportedException)
        {
            throw new OAuthDataException($"{path} is not valid JSON for No2SQL.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new OAuthDataException($"{path} cannot be read ({ex.GetType().Name}).");
        }
    }

    /// <summary>Writes a JSON file owner-only, atomically (temporary file, then rename over the old one).</summary>
    public void Write<T>(string name, T value)
    {
        var path = File(name);
        var temp = File($".{name}.{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = CreateOwnerOnly(temp))
            {
                JsonSerializer.Serialize(stream, value, Json);
                stream.Flush(flushToDisk: true);
            }

            System.IO.File.Move(temp, path, overwrite: true);
        }
        catch
        {
            TryDelete(temp);
            throw;
        }
    }

    /// <summary>Runs <paramref name="action"/> while holding the directory lock.</summary>
    /// <exception cref="OAuthDataException">The lock could not be taken in time, or the directory cannot be written.</exception>
    public T WithLock<T>(Func<T> action)
    {
        if (!_processLock.Wait(LockTimeout))
        {
            throw new OAuthDataException($"Timed out waiting for the lock on {Path}.");
        }

        try
        {
            using var fileLock = AcquireFileLock();
            return action();
        }
        finally
        {
            _processLock.Release();
        }
    }

    public void WithLock(Action action) => WithLock(() =>
    {
        action();
        return true;
    });

    private FileStream AcquireFileLock()
    {
        var path = File(LockFile);
        var deadline = DateTime.UtcNow + LockTimeout;
        while (true)
        {
            try
            {
                // FileShare.None takes an exclusive advisory lock (flock) on Unix and a sharing lock on Windows.
                return OperatingSystem.IsWindows()
                    ? new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None)
                    : new FileStream(path, new FileStreamOptions
                    {
                        Mode = FileMode.OpenOrCreate,
                        Access = FileAccess.ReadWrite,
                        Share = FileShare.None,
                        UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
                    });
            }
            catch (UnauthorizedAccessException)
            {
                throw new OAuthDataException($"Cannot write to {Path}.");
            }
            catch (DirectoryNotFoundException)
            {
                throw new OAuthDataException($"The data directory {Path} does not exist.");
            }
            catch (IOException) when (DateTime.UtcNow < deadline)
            {
                Thread.Sleep(20);
            }
            catch (IOException ex)
            {
                throw new OAuthDataException($"Timed out waiting for the lock on {Path} ({ex.GetType().Name}).");
            }
        }
    }

    private static FileStream CreateOwnerOnly(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            return new FileInfo(path).Create(FileMode.CreateNew, FileSystemRights.FullControl, FileShare.None, 4096, FileOptions.None, OwnerOnlyFileSecurity());
        }

        return new FileStream(path, new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.None,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
        });
    }

    private static void TryDelete(string path)
    {
        try
        {
            System.IO.File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Nothing to add: the original exception is the one that matters.
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static DirectorySecurity OwnerOnlyDirectorySecurity()
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(
            WindowsIdentity.GetCurrent().User!, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        return security;
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static FileSecurity OwnerOnlyFileSecurity()
    {
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!, FileSystemRights.FullControl, AccessControlType.Allow));
        return security;
    }
}

/// <summary>A data-directory file is missing, unreadable or corrupt. The message names the path, never a value.</summary>
internal sealed class OAuthDataException(string message) : Exception(message);
