using System.Security.Cryptography;
using System.Text.Json.Serialization;
using Microsoft.IdentityModel.Tokens;

namespace No2SQL.Hosting.OAuth;

/// <summary>
/// <c>clients.json</c>: clients registered by Dynamic Client Registration, and the owner's approvals of
/// Client ID Metadata Document clients (threat model R4, R13, R23).
/// <list type="bullet">
/// <item>At most <see cref="MaxClients"/> registrations. When full, the oldest never-approved one is evicted;
/// approved clients are never evicted, and when every client is approved a new registration is refused.</item>
/// <item>A CIMD approval is remembered for 30 days for the same client_id and redirect_uri.</item>
/// </list>
/// </summary>
internal sealed class ClientStore
{
    public const int DefaultMaxClients = 200;
    public static readonly TimeSpan ApprovalMemory = TimeSpan.FromDays(30);

    private readonly SharedDocument<ClientsDocument> _document;
    private readonly TimeProvider _clock;

    public ClientStore(OAuthDataDirectory directory, TimeProvider clock, int maxClients = DefaultMaxClients)
    {
        _clock = clock;
        MaxClients = maxClients;
        _document = new SharedDocument<ClientsDocument>(directory, OAuthDataDirectory.ClientsFile, clock);
    }

    public int MaxClients { get; }

    /// <summary>A registered (DCR) client, or null.</summary>
    public RegisteredClient? Find(string clientId) =>
        _document.Read().Clients.FirstOrDefault(c => string.Equals(c.ClientId, clientId, StringComparison.Ordinal));

    /// <summary>Stores a new registration, or returns null when the store is full of approved clients.</summary>
    public RegisteredClient? Register(string? clientName, IReadOnlyList<string> redirectUris) => _document.Update(document =>
    {
        if (document.Clients.Count >= MaxClients)
        {
            var evictable = document.Clients.Where(c => c.ApprovedAt is null).OrderBy(c => c.CreatedAt).FirstOrDefault();
            if (evictable is null)
            {
                return null;
            }

            document.Clients.Remove(evictable);
        }

        var client = new RegisteredClient
        {
            ClientId = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(16)),
            ClientName = clientName,
            RedirectUris = [.. redirectUris],
            CreatedAt = _clock.GetUtcNow(),
        };
        document.Clients.Add(client);
        return client;
    }, client => client is not null);

    /// <summary>Records the owner's approval: a DCR client is then never evicted; a CIMD client may skip the consent page for 30 days.</summary>
    public void RecordApproval(string clientId, string redirectUri, bool isMetadataDocumentClient) => _document.Update(document =>
    {
        var now = _clock.GetUtcNow();
        if (isMetadataDocumentClient)
        {
            document.Approvals.RemoveAll(a => a.ClientId == clientId && a.RedirectUri == redirectUri);
            document.Approvals.Add(new MetadataClientApproval { ClientId = clientId, RedirectUri = redirectUri, ApprovedAt = now });
        }
        else if (document.Clients.FirstOrDefault(c => c.ClientId == clientId) is { } client)
        {
            client.ApprovedAt = now;
        }

        return true;
    });

    /// <summary>True when the owner approved this CIMD client for this exact redirect_uri less than 30 days ago.</summary>
    public bool HasRecentApproval(string clientId, string redirectUri)
    {
        var now = _clock.GetUtcNow();
        return _document.Read().Approvals.Any(a =>
            string.Equals(a.ClientId, clientId, StringComparison.Ordinal)
            && string.Equals(a.RedirectUri, redirectUri, StringComparison.Ordinal)
            && now - a.ApprovedAt < ApprovalMemory);
    }

    /// <summary>The whole document, for <c>No2SQL oauth list</c>.</summary>
    public static ClientsDocument ReadAll(OAuthDataDirectory directory) =>
        directory.Read<ClientsDocument>(OAuthDataDirectory.ClientsFile) ?? new ClientsDocument();

    /// <summary><c>revoke &lt;client_id&gt;</c>: forgets the approval. Returns false when the client is unknown.</summary>
    public static bool RevokeApproval(OAuthDataDirectory directory, string clientId) => directory.WithLock(() =>
    {
        var document = directory.Read<ClientsDocument>(OAuthDataDirectory.ClientsFile) ?? new ClientsDocument();
        var found = document.Approvals.RemoveAll(a => a.ClientId == clientId) > 0;
        foreach (var client in document.Clients.Where(c => c.ClientId == clientId))
        {
            client.ApprovedAt = null;
            found = true;
        }

        if (found)
        {
            directory.Write(OAuthDataDirectory.ClientsFile, document);
        }

        return found;
    });

    /// <summary><c>revoke-all</c>: deletes never-approved registrations and every CIMD approval. Returns how many registrations were deleted.</summary>
    public static int RemoveUnapprovedAndApprovals(OAuthDataDirectory directory) => directory.WithLock(() =>
    {
        var document = directory.Read<ClientsDocument>(OAuthDataDirectory.ClientsFile) ?? new ClientsDocument();
        var removed = document.Clients.RemoveAll(c => c.ApprovedAt is null);
        document.Approvals.Clear();
        directory.Write(OAuthDataDirectory.ClientsFile, document);
        return removed;
    });
}

/// <summary>The JSON of <c>clients.json</c>.</summary>
internal sealed class ClientsDocument
{
    [JsonPropertyName("clients")]
    public List<RegisteredClient> Clients { get; set => field = value ?? []; } = [];

    [JsonPropertyName("approvals")]
    public List<MetadataClientApproval> Approvals { get; set => field = value ?? []; } = [];
}

/// <summary>A DCR registration: only the name and redirect URIs are kept (R7).</summary>
internal sealed class RegisteredClient
{
    [JsonPropertyName("client_id")] public string ClientId { get; set; } = "";
    [JsonPropertyName("client_name")] public string? ClientName { get; set; }
    [JsonPropertyName("redirect_uris")] public List<string> RedirectUris { get; set => field = value ?? []; } = [];
    [JsonPropertyName("created_at")] public DateTimeOffset CreatedAt { get; set; }
    [JsonPropertyName("approved_at")] public DateTimeOffset? ApprovedAt { get; set; }
}

/// <summary>The owner's approval of a CIMD client for one redirect_uri.</summary>
internal sealed class MetadataClientApproval
{
    [JsonPropertyName("client_id")] public string ClientId { get; set; } = "";
    [JsonPropertyName("redirect_uri")] public string RedirectUri { get; set; } = "";
    [JsonPropertyName("approved_at")] public DateTimeOffset ApprovedAt { get; set; }
}
