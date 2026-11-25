using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace No2SQL.Hosting.OAuth;

/// <summary>Resolves a host name to addresses. Replaced in tests (R32); not configurable.</summary>
internal interface IHostResolver
{
    Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken);
}

/// <summary>Decides whether a metadata-document fetch may connect to an address. Replaced in tests (R32); not configurable.</summary>
internal interface ICimdAddressPolicy
{
    bool IsAllowed(IPAddress address);
}

/// <summary>Creates the HTTP handler for metadata-document fetches. Replaced in tests (R32); not configurable.</summary>
internal delegate HttpMessageHandler CimdHandlerFactory(MetadataDocumentClients clients);

internal sealed class SystemHostResolver : IHostResolver
{
    public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) => Dns.GetHostAddressesAsync(host, cancellationToken);
}

/// <summary>
/// Public unicast addresses only (R8): refuses loopback, private, shared (CGNAT), link-local (including the
/// cloud metadata address 169.254.169.254), multicast, reserved, unspecified, documentation and benchmarking
/// ranges, IPv6 unique-local, site-local and link-local, IPv4-mapped forms of all of them, 6to4 forms of
/// private IPv4, Teredo, NAT64 and ORCHID.
/// </summary>
internal sealed class PublicAddressPolicy : ICimdAddressPolicy
{
    public bool IsAllowed(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            return IsPublicV4(address.MapToIPv4().GetAddressBytes());
        }

        var bytes = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            return IsPublicV4(bytes);
        }

        if (address.AddressFamily != AddressFamily.InterNetworkV6)
        {
            return false;
        }

        // Global unicast is 2000::/3; everything outside it (::, ::1, fc00::/7, fe80::/10, fec0::/10, ff00::/8, 64:ff9b::/96 ...) is refused.
        if ((bytes[0] & 0xE0) != 0x20)
        {
            return false;
        }

        var first16 = (bytes[0] << 8) | bytes[1];
        var second16 = (bytes[2] << 8) | bytes[3];
        if (first16 == 0x2001 && second16 == 0x0db8)
        {
            return false;   // 2001:db8::/32 documentation
        }

        if (first16 == 0x2001 && second16 < 0x0200)
        {
            return false;   // 2001::/23 IETF protocol assignments: Teredo, ORCHID, benchmarking
        }

        if (first16 == 0x3fff && (bytes[2] & 0xF0) == 0)
        {
            return false;   // 3fff::/20 documentation
        }

        if (first16 == 0x2002)
        {
            return IsPublicV4(bytes[2..6]);   // 6to4 carries an IPv4 address
        }

        return true;
    }

    private static bool IsPublicV4(byte[] b) => !(
        b[0] == 0                                        // 0.0.0.0/8
        || b[0] == 10                                    // 10.0.0.0/8
        || (b[0] == 100 && (b[1] & 0xC0) == 64)          // 100.64.0.0/10 shared address space
        || b[0] == 127                                   // loopback
        || (b[0] == 169 && b[1] == 254)                  // link-local, cloud metadata
        || (b[0] == 172 && (b[1] & 0xF0) == 16)          // 172.16.0.0/12
        || (b[0] == 192 && b[1] == 0 && b[2] == 0)       // 192.0.0.0/24 protocol assignments
        || (b[0] == 192 && b[1] == 0 && b[2] == 2)       // documentation
        || (b[0] == 192 && b[1] == 88 && b[2] == 99)     // 6to4 relay anycast
        || (b[0] == 192 && b[1] == 168)                  // 192.168.0.0/16
        || (b[0] == 198 && (b[1] & 0xFE) == 18)          // 198.18.0.0/15 benchmarking
        || (b[0] == 198 && b[1] == 51 && b[2] == 100)    // documentation
        || (b[0] == 203 && b[1] == 0 && b[2] == 113)     // documentation
        || b[0] >= 224);                                 // multicast, reserved, broadcast
}

/// <summary>
/// Client ID Metadata Document clients (threat model R8 to R10): a <c>client_id</c> that is an https URL is
/// fetched, under these limits, and becomes a client whose redirect URIs are on that URL's host.
/// <list type="bullet">
/// <item>Only <c>https://</c> on port 443 to a DNS name; every resolved address must be public, checked in the
/// connect callback so the connection goes to the checked address; no redirects; no proxy.</item>
/// <item>Connect 3 s, total 5 s, 64 KiB, <c>application/json</c>; at most 10 fetches a minute; one at a time per
/// host; successes cached 1 hour and failures 5 minutes, in memory only; never retried.</item>
/// </list>
/// </summary>
internal sealed class MetadataDocumentClients : IDisposable
{
    public static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(3);
    public static readonly TimeSpan TotalTimeout = TimeSpan.FromSeconds(5);
    public const int MaxDocumentBytes = 64 * 1024;
    public const int FetchesPerMinute = 10;
    public static readonly TimeSpan SuccessCache = TimeSpan.FromHours(1);
    public static readonly TimeSpan FailureCache = TimeSpan.FromMinutes(5);

    private static readonly string[] ReservedSuffixes = [".localhost", ".local", ".internal", ".localdomain", ".home.arpa"];

    private readonly IHostResolver _resolver;
    private readonly ICimdAddressPolicy _policy;
    private readonly TimeProvider _clock;
    private readonly ILogger _log;
    private readonly HttpClient _http;
    private readonly SlidingWindowLimiter _fetchLimit;

    private readonly Dictionary<string, (ResolvedClient? Client, DateTimeOffset Until)> _cache = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Task<ResolvedClient?>> _inFlight = new(StringComparer.Ordinal);
    private readonly Dictionary<string, SemaphoreSlim> _hostLocks = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    public MetadataDocumentClients(IHostResolver resolver, ICimdAddressPolicy policy, TimeProvider clock, ILogger<MetadataDocumentClients> log, CimdHandlerFactory handlerFactory)
    {
        _resolver = resolver;
        _policy = policy;
        _clock = clock;
        _log = log;
        _fetchLimit = new SlidingWindowLimiter(FetchesPerMinute, TimeSpan.FromMinutes(1), clock);
        _http = new HttpClient(handlerFactory(this), disposeHandler: true) { Timeout = Timeout.InfiniteTimeSpan };
    }

    /// <summary>The production handler: no proxy, no redirects, no cookies, 3 s connect, and the address check in the connect callback.</summary>
    public static HttpMessageHandler CreateHandler(MetadataDocumentClients clients) => new SocketsHttpHandler
    {
        UseProxy = false,
        AllowAutoRedirect = false,
        UseCookies = false,
        AutomaticDecompression = DecompressionMethods.None,
        ConnectTimeout = ConnectTimeout,
        PooledConnectionLifetime = TimeSpan.FromMinutes(1),
        MaxResponseHeadersLength = 16,   // KiB
        ConnectCallback = clients.ConnectAsync,
    };

    /// <summary>True when a client_id is meant as a metadata document URL (it starts with https://).</summary>
    public static bool IsMetadataDocumentUrl(string clientId) => clientId.StartsWith("https://", StringComparison.Ordinal);

    /// <summary>
    /// The URL rules that need no network (R8): https, port 443, a DNS name with a dot that is not an IP
    /// literal, localhost or a local-only suffix, a path, no user info or fragment. Returns the reason, or null.
    /// </summary>
    public static string? CheckUrl(string clientId)
    {
        if (clientId.Length > RedirectUriRules.MaxLength || clientId.Any(c => char.IsControl(c) || char.IsWhiteSpace(c) || c == '\\')
            || !Uri.TryCreate(clientId, UriKind.Absolute, out var uri))
        {
            return "not a valid URL";
        }

        if (uri.Scheme != Uri.UriSchemeHttps)
        {
            return "not https";
        }

        if (!string.IsNullOrEmpty(uri.UserInfo) || clientId.Contains('#'))
        {
            return "has user info or a fragment";
        }

        if (uri.Port != 443)
        {
            return "not on port 443";
        }

        if (uri.HostNameType != UriHostNameType.Dns)
        {
            return "the host is an IP address";
        }

        var host = uri.IdnHost.TrimEnd('.');
        if (!host.Contains('.') || string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
            || ReservedSuffixes.Any(s => host.EndsWith(s, StringComparison.OrdinalIgnoreCase)))
        {
            return "the host is not a public DNS name";
        }

        if (uri.AbsolutePath.Length <= 1)
        {
            return "the URL has no path";
        }

        return null;
    }

    /// <summary>The client described by the document at <paramref name="clientId"/>, or null when it cannot be used.</summary>
    public async Task<ResolvedClient?> ResolveAsync(string clientId, CancellationToken cancellationToken)
    {
        if (CheckUrl(clientId) is { } reason)
        {
            _log.LogWarning("Client metadata document refused: {Reason}.", reason);
            return null;
        }

        Task<ResolvedClient?> task;
        lock (_gate)
        {
            if (_cache.TryGetValue(clientId, out var cached) && cached.Until > _clock.GetUtcNow())
            {
                return cached.Client;
            }

            if (!_inFlight.TryGetValue(clientId, out task!))
            {
                task = FetchAndCacheAsync(clientId);
                _inFlight[clientId] = task;
            }
        }

        // The caller's cancellation stops the wait, not the shared fetch (which has its own 5 s limit).
        return await task.WaitAsync(cancellationToken);
    }

    public void Dispose() => _http.Dispose();

    private async Task<ResolvedClient?> FetchAndCacheAsync(string clientId)
    {
        var host = new Uri(clientId).IdnHost;
        ResolvedClient? client = null;
        var cacheable = true;
        try
        {
            if (!_fetchLimit.TryAcquire("global", out _))
            {
                cacheable = false;   // a busy minute is not the client's fault
                _log.LogWarning("Client metadata document from {Host} not fetched: more than {Limit} fetches in the last minute.", host, FetchesPerMinute);
                return null;
            }

            client = await FetchAsync(clientId, host);
            return client;
        }
        finally
        {
            lock (_gate)
            {
                _inFlight.Remove(clientId);
                if (cacheable)
                {
                    var now = _clock.GetUtcNow();
                    foreach (var stale in _cache.Where(c => c.Value.Until <= now).Select(c => c.Key).ToList())
                    {
                        _cache.Remove(stale);
                    }

                    _cache[clientId] = (client, now + (client is null ? FailureCache : SuccessCache));
                }
            }
        }
    }

    private async Task<ResolvedClient?> FetchAsync(string clientId, string host)
    {
        using var timeout = new CancellationTokenSource(TotalTimeout, _clock);
        SemaphoreSlim hostLock;
        lock (_gate)
        {
            if (!_hostLocks.TryGetValue(host, out hostLock!))
            {
                _hostLocks[host] = hostLock = new SemaphoreSlim(1, 1);
            }
        }

        try
        {
            await hostLock.WaitAsync(timeout.Token);
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, clientId);
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);

                if (response.StatusCode != HttpStatusCode.OK)
                {
                    return Refuse(host, $"HTTP {(int)response.StatusCode}");
                }

                if (!string.Equals(response.Content.Headers.ContentType?.MediaType, "application/json", StringComparison.OrdinalIgnoreCase))
                {
                    return Refuse(host, "the response is not application/json");
                }

                if (response.Content.Headers.ContentLength > MaxDocumentBytes)
                {
                    return Refuse(host, "the document is larger than 64 KiB");
                }

                var body = await ReadAtMostAsync(await response.Content.ReadAsStreamAsync(timeout.Token), MaxDocumentBytes, timeout.Token);
                if (body is null)
                {
                    return Refuse(host, "the document is larger than 64 KiB");
                }

                return Validate(clientId, host, body);
            }
            finally
            {
                hostLock.Release();
            }
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested)
        {
            return Refuse(host, "no complete answer within 5 seconds");
        }
        catch (Exception ex) when (ex is CimdAddressRefusedException || ex.InnerException is CimdAddressRefusedException)
        {
            return Refuse(host, "the host resolves to an address that is not public");
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or SocketException or System.Security.Authentication.AuthenticationException)
        {
            return Refuse(host, $"the fetch failed ({ex.GetType().Name})");
        }
    }

    // R10: the document's client_id is the URL, every redirect URI is on the same host (or loopback), and the client is public.
    private ResolvedClient? Validate(string clientId, string host, byte[] body)
    {
        try
        {
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("client_id", out var id) || id.ValueKind != JsonValueKind.String
                || !string.Equals(id.GetString(), clientId, StringComparison.Ordinal))
            {
                return Refuse(host, "the document's client_id is not the URL it was fetched from");
            }

            if (root.TryGetProperty("token_endpoint_auth_method", out var method)
                && (method.ValueKind != JsonValueKind.String || method.GetString() != "none"))
            {
                return Refuse(host, "token_endpoint_auth_method is not none");
            }

            if (!root.TryGetProperty("redirect_uris", out var uris) || uris.ValueKind != JsonValueKind.Array
                || uris.GetArrayLength() is 0 or > RedirectUriRules.MaxCount)
            {
                return Refuse(host, "redirect_uris is missing or has more than 10 entries");
            }

            var redirectUris = new List<string>();
            foreach (var entry in uris.EnumerateArray())
            {
                var value = entry.ValueKind == JsonValueKind.String ? entry.GetString() : null;
                if (!RedirectUriRules.IsAcceptable(value) || !OnHost(value!, host))
                {
                    return Refuse(host, "a redirect URI is not https on the client's own host");
                }

                redirectUris.Add(value!);
            }

            var name = root.TryGetProperty("client_name", out var n) && n.ValueKind == JsonValueKind.String ? ClientNames.Clean(n.GetString()) : null;
            _log.LogInformation("Client metadata document from {Host} accepted.", host);
            return new ResolvedClient(clientId, IsMetadataDocument: true, name, host, redirectUris);
        }
        catch (JsonException)
        {
            return Refuse(host, "the document is not valid JSON");
        }
    }

    private static bool OnHost(string redirectUri, string host)
    {
        var uri = new Uri(redirectUri);
        return uri.Scheme == Uri.UriSchemeHttp
            ? RedirectUriRules.IsLoopbackHost(uri)
            : string.Equals(uri.IdnHost.TrimEnd('.'), host.TrimEnd('.'), StringComparison.OrdinalIgnoreCase);
    }

    private ResolvedClient? Refuse(string host, string reason)
    {
        _log.LogWarning("Client metadata document from {Host} refused: {Reason}.", host, reason);
        return null;
    }

    private static async Task<byte[]?> ReadAtMostAsync(Stream stream, int limit, CancellationToken cancellationToken)
    {
        await using (stream)
        {
            var buffer = new byte[limit + 1];
            var total = 0;
            int read;
            while ((read = await stream.ReadAsync(buffer.AsMemory(total), cancellationToken)) > 0)
            {
                total += read;
                if (total > limit)
                {
                    return null;
                }
            }

            return buffer[..total];
        }
    }

    // Resolves the host, refuses unless every address is public, and connects to one of the checked addresses.
    private async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext context, CancellationToken cancellationToken)
    {
        var addresses = await _resolver.ResolveAsync(context.DnsEndPoint.Host, cancellationToken);
        if (addresses.Length == 0 || addresses.Any(a => !_policy.IsAllowed(a)))
        {
            throw new CimdAddressRefusedException();
        }

        SocketException? last = null;
        foreach (var address in addresses)
        {
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                await socket.ConnectAsync(new IPEndPoint(address, context.DnsEndPoint.Port), cancellationToken);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (SocketException ex)
            {
                socket.Dispose();
                last = ex;
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }

        throw last!;
    }
}

/// <summary>A metadata-document host resolved to a non-public address.</summary>
internal sealed class CimdAddressRefusedException() : IOException("The host resolves to an address that is not public.");
