using System.Net;
using Microsoft.AspNetCore.Http;

namespace No2SQL.Hosting;

/// <summary>One address HTTP mode listens on, already classified as loopback-only or not.</summary>
/// <param name="Host">"localhost", an IP literal, or "*" for every interface.</param>
/// <param name="Address">The parsed IP address, or null for "localhost" and for every interface.</param>
/// <param name="Port">The TCP port.</param>
/// <param name="IsLoopback">True when only this machine can reach the address.</param>
internal sealed record HttpBinding(string Host, IPAddress? Address, int Port, bool IsLoopback)
{
    public bool IsLocalhostName => Address is null && IsLoopback;

    public string DisplayUrl => Address is { AddressFamily: System.Net.Sockets.AddressFamily.InterNetworkV6 }
        ? $"http://[{Address}]:{Port}"
        : $"http://{Address?.ToString() ?? Host}:{Port}";
}

/// <summary>
/// Reads NO2SQL_HTTP_URLS, the only place HTTP mode takes its listen addresses from. Kestrel is
/// configured from the parsed result (see <see cref="HttpServer"/>), so what is validated here is
/// exactly what gets bound.
/// </summary>
internal static class HttpBindings
{
    public const string UrlsVariable = "NO2SQL_HTTP_URLS";
    public const string DefaultUrls = "http://127.0.0.1:8787";

    public static bool TryParse(string? value, out IReadOnlyList<HttpBinding> bindings, out string? error)
    {
        var list = new List<HttpBinding>();
        bindings = list;

        var urls = string.IsNullOrWhiteSpace(value) ? DefaultUrls : value;
        foreach (var raw in urls.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            BindingAddress address;
            try
            {
                address = BindingAddress.Parse(raw);
            }
            catch (FormatException)
            {
                error = $"{UrlsVariable} has an entry that is not a URL. Use the form http://127.0.0.1:8787, separated by ';'.";
                return false;
            }

            if (address.IsUnixPipe || address.IsNamedPipe)
            {
                error = $"{UrlsVariable} supports TCP addresses only, for example http://127.0.0.1:8787.";
                return false;
            }

            if (!string.Equals(address.Scheme, "http", StringComparison.OrdinalIgnoreCase))
            {
                error = $"{UrlsVariable} supports http:// addresses only. For HTTPS, put a TLS-terminating reverse proxy in front of No2SQL.";
                return false;
            }

            if (!string.IsNullOrEmpty(address.PathBase))
            {
                error = $"{UrlsVariable} entries must not contain a path. The MCP endpoint is always {HttpServer.McpPath}.";
                return false;
            }

            if (address.Port is < 1 or > 65535)
            {
                error = $"{UrlsVariable} has an entry with a port outside 1-65535.";
                return false;
            }

            list.Add(Classify(address.Host, address.Port));
        }

        if (list.Count == 0)
        {
            error = $"{UrlsVariable} contains no address.";
            return false;
        }

        error = null;
        return true;
    }

    // Mirrors how Kestrel treats a URL host: "localhost" is both loopback addresses, an IP literal is
    // that address, and anything else (a wildcard or a host name) means every interface.
    private static HttpBinding Classify(string host, int port)
    {
        if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase))
        {
            return new HttpBinding("localhost", null, port, IsLoopback: true);
        }

        var literal = host.StartsWith('[') && host.EndsWith(']') ? host[1..^1] : host;
        if (IPAddress.TryParse(literal, out var ip))
        {
            return new HttpBinding(literal, ip, port, IPAddress.IsLoopback(ip));
        }

        return new HttpBinding("*", null, port, IsLoopback: false);
    }
}
