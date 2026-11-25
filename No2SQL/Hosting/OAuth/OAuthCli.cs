using System.Globalization;

namespace No2SQL.Hosting.OAuth;

/// <summary>
/// <c>No2SQL oauth list | revoke &lt;client_id&gt; | revoke-all | rotate-keys</c> (threat model R23): the owner's
/// commands for the built-in authorization server. They change the data directory directly; a running server
/// picks the change up within a second. There is no HTTP admin endpoint. Nothing secret is ever printed.
/// </summary>
internal static class OAuthCli
{
    public const string Command = "oauth";

    private const string Usage = """
        Usage: No2SQL oauth <command>
          list                  show registered clients, approvals, live grants and signing keys
          revoke <client_id>    delete one client's refresh tokens and approval, refuse its access tokens
          revoke-all            delete every refresh token and never-approved client, replace the signing key
                                (every client must sign in again; access tokens stop working within a second)
          rotate-keys           new signing key; the old one keeps validating until its tokens expire
        The data directory is NO2SQL_DATA_DIR, or ~/.no2sql.
        """;

    /// <returns>The exit code: 0 done, 1 failed, 2 wrong usage.</returns>
    public static int Run(string[] args, Func<string, string?> getVariable, TimeProvider clock, TextWriter output, TextWriter error)
    {
        if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
        {
            (args.Length == 0 ? error : output).WriteLine(Usage);
            return args.Length == 0 ? 2 : 0;
        }

        if (!HttpAuthOptions.TryResolveDataDirectory(getVariable, out var path, out var problem))
        {
            error.WriteLine($"[No2SQL] {problem}");
            return 2;
        }

        var directory = new OAuthDataDirectory(path!);
        try
        {
            return (args[0], args.Length) switch
            {
                ("list", 1) => List(directory, clock, output, error),
                ("revoke", 2) => Revoke(directory, args[1], clock, output, error),
                ("revoke-all", 1) => RevokeAll(directory, output, error),
                ("rotate-keys", 1) => RotateKeys(directory, getVariable, clock, output, error),
                _ => WrongUsage(error),
            };
        }
        catch (OAuthDataException ex)
        {
            error.WriteLine($"[No2SQL] {ex.Message}");
            return 1;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            error.WriteLine($"[No2SQL] Cannot write to {directory.Path} ({ex.GetType().Name}). Run the command as the user that runs the server.");
            return 1;
        }
    }

    private static int WrongUsage(TextWriter error)
    {
        error.WriteLine(Usage);
        return 2;
    }

    private static bool Exists(OAuthDataDirectory directory, TextWriter error)
    {
        if (Directory.Exists(directory.Path))
        {
            return true;
        }

        error.WriteLine($"[No2SQL] There is no data directory at {directory.Path}. Start the server once with {HttpAuthOptions.BuiltinVariable}=true, or set {HttpAuthOptions.DataDirectoryVariable}.");
        return false;
    }

    private static int List(OAuthDataDirectory directory, TimeProvider clock, TextWriter output, TextWriter error)
    {
        if (!Exists(directory, error))
        {
            return 1;
        }

        var now = clock.GetUtcNow();
        var clients = ClientStore.ReadAll(directory);
        var grants = GrantStore.CountByClient(directory, now);
        output.WriteLine($"Data directory: {directory.Path}");

        output.WriteLine();
        output.WriteLine("Registered clients (dynamic registration, shown to you as unverified):");
        if (clients.Clients.Count == 0)
        {
            output.WriteLine("  none");
        }

        foreach (var client in clients.Clients.OrderBy(c => c.CreatedAt))
        {
            var hosts = string.Join(", ", client.RedirectUris.Select(RedirectUriRules.Describe).Distinct());
            var approved = client.ApprovedAt is { } at ? $"approved {Format(at)}" : "never approved";
            output.WriteLine($"  {client.ClientId}  \"{client.ClientName ?? "(no name)"}\"  redirects to {hosts}; registered {Format(client.CreatedAt)}, {approved}; {grants.GetValueOrDefault(client.ClientId)} live grant(s)");
        }

        output.WriteLine();
        output.WriteLine("Clients with a metadata document (approvals remembered for 30 days):");
        var metadataClients = clients.Approvals.Select(a => a.ClientId)
            .Concat(grants.Keys.Where(MetadataDocumentClients.IsMetadataDocumentUrl))
            .Distinct(StringComparer.Ordinal).ToList();
        if (metadataClients.Count == 0)
        {
            output.WriteLine("  none");
        }

        foreach (var clientId in metadataClients)
        {
            var approvals = clients.Approvals.Where(a => a.ClientId == clientId)
                .Select(a => $"{RedirectUriRules.Describe(a.RedirectUri)} approved {Format(a.ApprovedAt)}").ToList();
            output.WriteLine($"  {clientId}  {(approvals.Count == 0 ? "no remembered approval" : string.Join("; ", approvals))}; {grants.GetValueOrDefault(clientId)} live grant(s)");
        }

        output.WriteLine();
        output.WriteLine("Signing keys:");
        foreach (var (kid, status, retireAt) in SigningKeyStore.Describe(directory))
        {
            output.WriteLine($"  {kid}  {status}{(retireAt is { } at ? $" until {Format(at)}" : "")}");
        }

        return 0;
    }

    private static int Revoke(OAuthDataDirectory directory, string clientId, TimeProvider clock, TextWriter output, TextWriter error)
    {
        if (!Exists(directory, error))
        {
            return 1;
        }

        var families = GrantStore.RevokeClient(directory, clientId, clock.GetUtcNow());
        var hadApproval = ClientStore.RevokeApproval(directory, clientId);
        if (families == 0 && !hadApproval)
        {
            error.WriteLine($"[No2SQL] No client {clientId} has an approval or a grant. 'No2SQL oauth list' shows the clients.");
            return 1;
        }

        output.WriteLine($"Revoked {clientId}: {families} grant(s) deleted, its access tokens refused, approval forgotten. A running server applies this within a second.");
        return 0;
    }

    private static int RevokeAll(OAuthDataDirectory directory, TextWriter output, TextWriter error)
    {
        if (!Exists(directory, error))
        {
            return 1;
        }

        var families = GrantStore.RevokeAll(directory);
        var removed = ClientStore.RemoveUnapprovedAndApprovals(directory);
        var kid = SigningKeyStore.ReplaceAll(directory);
        output.WriteLine($"Revoked everything: {families} grant(s) deleted, {removed} never-approved client(s) deleted, remembered approvals forgotten, new signing key {kid}.");
        output.WriteLine("Every access token stops working within a second; every client has to sign in again.");
        return 0;
    }

    private static int RotateKeys(OAuthDataDirectory directory, Func<string, string?> getVariable, TimeProvider clock, TextWriter output, TextWriter error)
    {
        if (!Exists(directory, error))
        {
            return 1;
        }

        // The old key must validate every token it signed: the access-token lifetime (as the server reads it) plus the skew.
        var minutes = HttpAuthOptions.DefaultAccessTokenMinutes;
        var configured = getVariable(HttpAuthOptions.AccessTokenMinutesVariable)?.Trim();
        if (!string.IsNullOrEmpty(configured)
            && (!int.TryParse(configured, NumberStyles.None, CultureInfo.InvariantCulture, out minutes)
                || minutes is < HttpAuthOptions.MinimumAccessTokenMinutes or > HttpAuthOptions.MaximumAccessTokenMinutes))
        {
            error.WriteLine($"[No2SQL] {HttpAuthOptions.AccessTokenMinutesVariable} must be a whole number of minutes from {HttpAuthOptions.MinimumAccessTokenMinutes} to {HttpAuthOptions.MaximumAccessTokenMinutes}.");
            return 2;
        }

        var (newKid, retiringKid, retireAt) = SigningKeyStore.Rotate(directory, clock.GetUtcNow(), TimeSpan.FromMinutes(minutes) + HttpAuth.ClockSkew);
        output.WriteLine($"New signing key {newKid}.{(retiringKid is null ? "" : $" The previous key {retiringKid} keeps validating tokens until {Format(retireAt)}.")}");
        return 0;
    }

    private static string Format(DateTimeOffset time) => time.UtcDateTime.ToString("yyyy-MM-dd HH:mm 'UTC'", CultureInfo.InvariantCulture);
}
