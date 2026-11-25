using System.Globalization;
using System.Net;

namespace No2SQL.Hosting;

/// <summary>
/// The hardening settings of HTTP mode (P2-6), read once at start-up from NO2SQL_HTTP_* variables.
/// Every setting is optional; the defaults suit a server behind a reverse proxy on the same host.
/// </summary>
internal sealed record HttpHardeningOptions
{
    public const string AllowedHostsVariable = "NO2SQL_HTTP_ALLOWED_HOSTS";
    public const string AllowedOriginsVariable = "NO2SQL_HTTP_ALLOWED_ORIGINS";
    public const string TrustedProxiesVariable = "NO2SQL_HTTP_TRUSTED_PROXIES";
    public const string MaxBodyBytesVariable = "NO2SQL_HTTP_MAX_BODY_BYTES";
    public const string RequestTimeoutVariable = "NO2SQL_HTTP_REQUEST_TIMEOUT_SECONDS";
    public const string RateLimitVariable = "NO2SQL_HTTP_RATE_LIMIT_PER_MINUTE";
    public const string RateLimitPerIpVariable = "NO2SQL_HTTP_RATE_LIMIT_PER_IP_PER_MINUTE";
    public const string MaxConcurrentCallsVariable = "NO2SQL_HTTP_MAX_CONCURRENT_CALLS";
    public const string MaxConnectionsVariable = "NO2SQL_HTTP_MAX_CONNECTIONS";
    public const string HstsVariable = "NO2SQL_HTTP_HSTS";

    // Set by P2-4 (the https:// origin clients use). Read here only for the host, origin and HSTS defaults.
    public const string PublicUrlVariable = "NO2SQL_PUBLIC_URL";

    private static readonly string[] LoopbackHosts = ["localhost", "127.0.0.1", "[::1]"];

    public required IReadOnlyList<string> AllowedHosts { get; init; }

    /// <summary>Normalised origins: lower-case scheme and host, explicit port ("https://example.com:443").</summary>
    public required IReadOnlySet<string> AllowedOrigins { get; init; }

    public IReadOnlyList<IPNetwork> TrustedProxies { get; init; } = [];

    public long MaxBodyBytes { get; init; } = 1024 * 1024;

    public TimeSpan RequestTimeout { get; init; } = TimeSpan.FromSeconds(120);

    public int RateLimitPerMinute { get; init; } = 60;

    public int RateLimitPerIpPerMinute { get; init; } = 300;

    public int MaxConcurrentCalls { get; init; } = 16;

    public int MaxConnections { get; init; } = 256;

    public bool Hsts { get; init; }

    /// <summary>
    /// The length of a rate-limit "minute". Always one minute in the shipped server; tests shorten it
    /// because the framework's fixed-window limiter runs on the system clock, not on TimeProvider.
    /// </summary>
    public TimeSpan RateLimitWindow { get; init; } = TimeSpan.FromMinutes(1);

    /// <summary>Start-up warnings about the effective configuration (never contains a secret).</summary>
    public IReadOnlyList<string> Warnings { get; init; } = [];

    /// <summary>The defaults for the default listen address, as the test host uses them.</summary>
    public static HttpHardeningOptions Defaults { get; } = CreateDefaults();

    private static HttpHardeningOptions CreateDefaults()
    {
        HttpBindings.TryParse(null, out var bindings, out _);
        TryParse(_ => null, bindings, out var options, out _);
        return options!;
    }

    public static bool TryParse(
        Func<string, string?> readVariable,
        IReadOnlyList<HttpBinding> bindings,
        out HttpHardeningOptions? options,
        out string? error)
    {
        options = null;
        var warnings = new List<string>();

        Uri? publicUrl = null;
        var publicUrlText = readVariable(PublicUrlVariable);
        if (!string.IsNullOrWhiteSpace(publicUrlText)
            && !TryParseOrigin(publicUrlText.Trim(), allowPath: true, out publicUrl))
        {
            error = $"{PublicUrlVariable} must be an absolute http:// or https:// URL, for example https://no2sql.example.com.";
            return false;
        }

        var wildcardBind = bindings.Any(IsWildcard);

        // Hosts.
        List<string> hosts;
        var hostsText = readVariable(AllowedHostsVariable);
        if (!string.IsNullOrWhiteSpace(hostsText))
        {
            hosts = SplitList(hostsText);
            if (hosts.Any(h => h == "*"))
            {
                error = $"{AllowedHostsVariable} must not contain '*': list the host names clients use, for example no2sql.example.com.";
                return false;
            }
        }
        else
        {
            hosts = [];
            if (publicUrl is not null)
            {
                hosts.Add(publicUrl.IdnHost);
            }

            hosts.AddRange(bindings.Where(b => !IsWildcard(b)).Select(HostOf));
            hosts.AddRange(LoopbackHosts);
            if (wildcardBind && publicUrl is null)
            {
                warnings.Add(
                    $"{string.Join(", ", bindings.Where(IsWildcard).Select(b => b.DisplayUrl))} listens on every interface, but only " +
                    $"{string.Join(", ", LoopbackHosts)} are accepted as Host. Remote callers get 400 until {PublicUrlVariable} or {AllowedHostsVariable} is set.");
            }
        }

        // Origins.
        var origins = new HashSet<string>(StringComparer.Ordinal);
        var originsText = readVariable(AllowedOriginsVariable);
        if (!string.IsNullOrWhiteSpace(originsText))
        {
            foreach (var entry in SplitList(originsText))
            {
                if (!TryParseOrigin(entry, allowPath: false, out var origin))
                {
                    error = $"{AllowedOriginsVariable} has an entry that is not an origin. Use the form https://host[:port], separated by ','.";
                    return false;
                }

                origins.Add(Normalize(origin));
            }
        }
        else
        {
            if (publicUrl is not null)
            {
                origins.Add(Normalize(publicUrl));
            }

            foreach (var port in bindings.Select(b => b.Port).Distinct())
            {
                foreach (var host in LoopbackHosts)
                {
                    origins.Add($"http://{host}:{port}");
                }
            }
        }

        // Trusted proxies.
        var proxies = new List<IPNetwork>();
        foreach (var entry in SplitList(readVariable(TrustedProxiesVariable)))
        {
            if (IPNetwork.TryParse(entry, out var network))
            {
                proxies.Add(network);
            }
            else if (IPAddress.TryParse(entry, out var address))
            {
                proxies.Add(new IPNetwork(address, address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 128 : 32));
            }
            else
            {
                error = $"{TrustedProxiesVariable} has an entry that is not an IP address or CIDR range, for example 172.30.0.0/24.";
                return false;
            }
        }

        if (!TryReadNumber(readVariable, MaxBodyBytesVariable, 1048576, 1024, long.MaxValue, out var maxBody, out error)
            || !TryReadNumber(readVariable, RequestTimeoutVariable, 120, 1, 3600, out var timeout, out error)
            || !TryReadNumber(readVariable, RateLimitVariable, 60, 1, 100_000, out var perToken, out error)
            || !TryReadNumber(readVariable, RateLimitPerIpVariable, 300, 1, 1_000_000, out var perIp, out error)
            || !TryReadNumber(readVariable, MaxConcurrentCallsVariable, 16, 1, 10_000, out var concurrent, out error)
            || !TryReadNumber(readVariable, MaxConnectionsVariable, 256, 1, 100_000, out var connections, out error))
        {
            return false;
        }

        var hsts = publicUrl?.Scheme == Uri.UriSchemeHttps;
        var hstsText = readVariable(HstsVariable);
        if (!string.IsNullOrWhiteSpace(hstsText))
        {
            switch (hstsText.Trim().ToLowerInvariant())
            {
                case "true" or "1" or "yes":
                    hsts = true;
                    break;
                case "false" or "0" or "no":
                    hsts = false;
                    break;
                default:
                    error = $"{HstsVariable} must be true or false.";
                    return false;
            }
        }

        options = new HttpHardeningOptions
        {
            AllowedHosts = hosts.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            AllowedOrigins = origins,
            TrustedProxies = proxies,
            MaxBodyBytes = maxBody,
            RequestTimeout = TimeSpan.FromSeconds(timeout),
            RateLimitPerMinute = (int)perToken,
            RateLimitPerIpPerMinute = (int)perIp,
            MaxConcurrentCalls = (int)concurrent,
            MaxConnections = (int)connections,
            Hsts = hsts,
            Warnings = warnings,
        };
        error = null;
        return true;
    }

    /// <summary>True when an Origin header value is one of <see cref="AllowedOrigins"/>; "null" never is.</summary>
    public bool IsAllowedOrigin(string origin) =>
        TryParseOrigin(origin, allowPath: false, out var parsed) && AllowedOrigins.Contains(Normalize(parsed));

    /// <summary>One line with every effective value, for the start-up log. It holds no secret.</summary>
    public string Summary() =>
        $"allowed hosts {string.Join(",", AllowedHosts)}; allowed origins {string.Join(",", AllowedOrigins.Order(StringComparer.Ordinal))}; " +
        $"trusted proxies {(TrustedProxies.Count == 0 ? "none" : string.Join(",", TrustedProxies))}; " +
        $"max body {MaxBodyBytes} bytes; request timeout {RequestTimeout.TotalSeconds:0} s; " +
        $"rate limit {RateLimitPerMinute}/min per token, {RateLimitPerIpPerMinute}/min per IP; " +
        $"max concurrent calls {MaxConcurrentCalls}; max connections {MaxConnections}; HSTS {(Hsts ? "on" : "off")}";

    private static bool IsWildcard(HttpBinding binding) =>
        binding.Host == "*" || IPAddress.Any.Equals(binding.Address) || IPAddress.IPv6Any.Equals(binding.Address);

    private static string HostOf(HttpBinding binding) =>
        binding.Address is { AddressFamily: System.Net.Sockets.AddressFamily.InterNetworkV6 } ? $"[{binding.Address}]" : binding.Host;

    private static string Normalize(Uri origin) =>
        $"{origin.Scheme.ToLowerInvariant()}://{origin.Host.ToLowerInvariant()}:{origin.Port.ToString(CultureInfo.InvariantCulture)}";

    private static bool TryParseOrigin(string text, bool allowPath, out Uri origin)
    {
        origin = null!;
        if (!Uri.TryCreate(text, UriKind.Absolute, out var uri)
            || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment)
            || (!allowPath && uri.AbsolutePath != "/"))
        {
            return false;
        }

        origin = uri;
        return true;
    }

    private static List<string> SplitList(string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? []
            : [.. value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)];

    private static bool TryReadNumber(
        Func<string, string?> readVariable, string name, long defaultValue, long min, long max, out long value, out string? error)
    {
        error = null;
        var text = readVariable(name);
        if (string.IsNullOrWhiteSpace(text))
        {
            value = defaultValue;
            return true;
        }

        if (long.TryParse(text.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out value) && value >= min && value <= max)
        {
            return true;
        }

        error = $"{name} must be a whole number from {min} to {max}.";
        return false;
    }
}
