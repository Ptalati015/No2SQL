using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

namespace No2SQL.Hosting.OAuth;

/// <summary>Everything the built-in authorization server's endpoints use, as one singleton.</summary>
internal sealed class OAuthServer(
    HttpAuthOptions auth,
    ClientStore clients,
    GrantStore grants,
    AuthorizationCodeStore codes,
    InteractionStore interactions,
    LoginThrottle throttle,
    OwnerCredential owner,
    MetadataDocumentClients metadataClients,
    AccessTokenIssuer tokens,
    SigningKeyStore keys,
    TimeProvider clock,
    ILoggerFactory loggers)
{
    public const int RegistrationsPerHour = 10;
    public const int TokenRequestsPerMinute = 30;

    public ILogger Log { get; } = loggers.CreateLogger("No2SQL.OAuth");
    public ClientStore Clients => clients;
    public GrantStore Grants => grants;
    public AuthorizationCodeStore Codes => codes;
    public InteractionStore Interactions => interactions;
    public LoginThrottle Throttle => throttle;
    public OwnerCredential Owner => owner;
    public AccessTokenIssuer Tokens => tokens;
    public SigningKeyStore Keys => keys;
    public TimeProvider Clock => clock;

    public SlidingWindowLimiter RegisterLimit { get; } = new(RegistrationsPerHour, TimeSpan.FromHours(1), clock);
    public SlidingWindowLimiter TokenLimit { get; } = new(TokenRequestsPerMinute, TimeSpan.FromMinutes(1), clock);

    public string McpUrl => auth.McpUrl!;

    /// <summary>The RFC 8414 metadata: exactly the keys of R2, in that order, from configuration only.</summary>
    public string MetadataJson { get; } = JsonSerializer.Serialize(new Dictionary<string, object>
    {
        ["issuer"] = auth.Issuer!,
        ["authorization_endpoint"] = auth.Issuer + OAuthServerEndpoints.AuthorizePath,
        ["token_endpoint"] = auth.Issuer + OAuthServerEndpoints.TokenPath,
        ["jwks_uri"] = auth.Issuer + OAuthServerEndpoints.JwksPath,
        ["registration_endpoint"] = auth.Issuer + OAuthServerEndpoints.RegisterPath,
        ["scopes_supported"] = OAuthServerEndpoints.Scopes,
        ["response_types_supported"] = new[] { "code" },
        ["grant_types_supported"] = new[] { "authorization_code", "refresh_token" },
        ["code_challenge_methods_supported"] = new[] { "S256" },
        ["token_endpoint_auth_methods_supported"] = new[] { "none" },
        ["client_id_metadata_document_supported"] = true,
    });

    /// <summary>The RFC 8707 resource is this server's MCP URL (scheme and host compared case-insensitively, a trailing slash ignored).</summary>
    public bool IsMcpResource(string? resource) =>
        resource is not null
        && Uri.TryCreate(resource, UriKind.Absolute, out var uri)
        && string.IsNullOrEmpty(uri.Query) && string.IsNullOrEmpty(uri.Fragment) && string.IsNullOrEmpty(uri.UserInfo)
        && string.Equals(uri.GetLeftPart(UriPartial.Authority), auth.Issuer, StringComparison.OrdinalIgnoreCase)
        && string.Equals(uri.AbsolutePath.TrimEnd('/'), HttpServer.McpPath, StringComparison.Ordinal);

    /// <summary>R17: the Origin header is the public URL's origin; without an Origin, the Referer is one of our pages. Neither means no.</summary>
    public bool IsSameOrigin(HttpRequest request)
    {
        var origin = request.Headers.Origin;
        if (origin.Count > 0)
        {
            return origin.Count == 1 && string.Equals(origin[0], auth.Issuer, StringComparison.OrdinalIgnoreCase);
        }

        var referer = request.Headers.Referer;
        return referer.Count == 1 && referer[0] is { } value && value.StartsWith(auth.Issuer + "/", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>A DCR client from the store, or a CIMD client fetched from its URL; null when neither.</summary>
    public async Task<ResolvedClient?> ResolveClientAsync(string clientId, CancellationToken cancellationToken)
    {
        if (MetadataDocumentClients.IsMetadataDocumentUrl(clientId))
        {
            return await metadataClients.ResolveAsync(clientId, cancellationToken);
        }

        return clients.Find(clientId) is { } registered
            ? new ResolvedClient(registered.ClientId, IsMetadataDocument: false, registered.ClientName, null, registered.RedirectUris)
            : null;
    }
}

/// <summary>Registration of the built-in authorization server, and its start-up checks.</summary>
internal static class OAuthServerSetup
{
    public static void AddNo2SqlOAuthServer(this IServiceCollection services, HttpAuthOptions auth)
    {
        services.TryAddSingleton(_ =>
        {
            var directory = new OAuthDataDirectory(auth.DataDirectory!);
            directory.EnsureExists();
            SigningKeyStore.EnsureCreated(directory);
            return directory;
        });
        services.TryAddSingleton<SigningKeyStore>();
        services.TryAddSingleton(sp => new ClientStore(sp.GetRequiredService<OAuthDataDirectory>(), sp.GetRequiredService<TimeProvider>()));
        services.TryAddSingleton<GrantStore>();
        services.TryAddSingleton<AuthorizationCodeStore>();
        services.TryAddSingleton<InteractionStore>();
        services.TryAddSingleton<LoginThrottle>();
        services.TryAddSingleton<IHostResolver, SystemHostResolver>();
        services.TryAddSingleton<ICimdAddressPolicy, PublicAddressPolicy>();
        services.TryAddSingleton<CimdHandlerFactory>(MetadataDocumentClients.CreateHandler);
        services.TryAddSingleton<MetadataDocumentClients>();
        services.TryAddSingleton<AccessTokenIssuer>();
        services.TryAddSingleton(sp => OwnerCredential.Resolve(auth.OwnerPassword, sp.GetRequiredService<OAuthDataDirectory>(), sp.GetRequiredService<TimeProvider>()).Credential);
        services.TryAddSingleton<OAuthServer>();
    }

    /// <summary>
    /// Start-up for <c>NO2SQL_OAUTH_BUILTIN=true</c>: creates the data directory owner-only, checks its
    /// permissions, creates or checks the signing keys and the other files, and resolves the owner password.
    /// Returns the reason when the server must not start (R25, R26).
    /// </summary>
    public static string? Prepare(HttpAuthOptions auth, TimeProvider clock, out OAuthDataDirectory directory, out OwnerCredential? credential, out string? generatedPassword, out List<string> warnings)
    {
        directory = new OAuthDataDirectory(auth.DataDirectory!);
        credential = null;
        generatedPassword = null;
        warnings = [];
        try
        {
            directory.EnsureExists();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return $"Cannot create the data directory {directory.Path} ({ex.GetType().Name}). Set {HttpAuthOptions.DataDirectoryVariable} to a directory No2SQL can write.";
        }

        (warnings, var refusal) = directory.CheckPermissions();
        if (refusal is not null)
        {
            return refusal;
        }

        try
        {
            directory.EnsureWritable();
        }
        catch (OAuthDataException ex)
        {
            return $"{ex.Message} Set {HttpAuthOptions.DataDirectoryVariable} to a directory the user running No2SQL can write.";
        }

        try
        {
            SigningKeyStore.EnsureCreated(directory);
            _ = directory.Read<ClientsDocument>(OAuthDataDirectory.ClientsFile);
            _ = directory.Read<GrantsDocument>(OAuthDataDirectory.GrantsFile);
            (credential, generatedPassword) = OwnerCredential.Resolve(auth.OwnerPassword, directory, clock);
        }
        catch (OAuthDataException ex)
        {
            return ex.Message;
        }

        return null;
    }
}
