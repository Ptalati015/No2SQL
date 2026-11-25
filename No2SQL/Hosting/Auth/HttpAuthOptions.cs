using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace No2SQL.Hosting;

/// <summary>
/// How HTTP mode checks callers, read from the environment once at start-up (P2-4).
/// <list type="bullet">
/// <item><c>NO2SQL_HTTP_TOKEN</c>: one static bearer token (scripts, the OpenAI Responses API).</item>
/// <item><c>NO2SQL_OAUTH_AUTHORITY</c> + <c>NO2SQL_PUBLIC_URL</c>: JWT access tokens from an external
/// identity provider, with protected resource metadata (RFC 9728) for OAuth clients.</item>
/// <item><c>NO2SQL_OAUTH_BUILTIN=true</c> + <c>NO2SQL_PUBLIC_URL</c>: the built-in single-owner authorization
/// server (P2-5) issues the JWT access tokens, with <c>NO2SQL_OWNER_PASSWORD</c> (or a generated password)
/// and its state in <c>NO2SQL_DATA_DIR</c>.</item>
/// </list>
/// The static token may be combined with either OAuth mode; the two OAuth modes exclude each other. With neither, HTTP mode is anonymous, which only a loopback address or
/// an explicit <c>--allow-anonymous</c> permits (see <see cref="HttpServer"/>).
/// </summary>
internal sealed partial record HttpAuthOptions
{
    public const string TokenVariable = "NO2SQL_HTTP_TOKEN";
    public const string AuthorityVariable = "NO2SQL_OAUTH_AUTHORITY";
    public const string PublicUrlVariable = "NO2SQL_PUBLIC_URL";
    public const string ScopeVariable = "NO2SQL_OAUTH_SCOPE";
    public const string BuiltinVariable = "NO2SQL_OAUTH_BUILTIN";
    public const string OwnerPasswordVariable = "NO2SQL_OWNER_PASSWORD";
    public const string DataDirectoryVariable = "NO2SQL_DATA_DIR";
    public const string AccessTokenMinutesVariable = "NO2SQL_OAUTH_ACCESS_TOKEN_MINUTES";

    public const string DefaultScope = "mcp:tools";
    public const int MinimumTokenLength = 32;
    public const int MinimumOwnerPasswordLength = 12;
    public const int DefaultAccessTokenMinutes = 60;
    public const int MinimumAccessTokenMinutes = 5;
    public const int MaximumAccessTokenMinutes = 1440;

    // Well-known path of the protected resource metadata for the resource <public URL>/mcp (RFC 9728 section 3.1).
    public const string ResourceMetadataPath = "/.well-known/oauth-protected-resource" + HttpServer.McpPath;

    // Values that docs and tutorials use as stand-ins. A token containing one is not a random secret.
    private static readonly string[] PlaceholderWords =
        ["example", "changeme", "change-me", "change_me", "replace", "placeholder", "yourtoken", "your-token", "your_token", "secret-token", "tokenhere", "token-here"];

    /// <summary>No sign-in: anonymous HTTP mode.</summary>
    public static HttpAuthOptions None { get; } = new();

    /// <summary>The static bearer token, or null when <c>NO2SQL_HTTP_TOKEN</c> is not set.</summary>
    public string? StaticToken { get; init; }

    /// <summary>The external identity provider's issuer, exactly as configured, or null.</summary>
    public string? Authority { get; init; }

    /// <summary>The public base URL clients use (scheme, host and port only), or null.</summary>
    public Uri? PublicUrl { get; init; }

    /// <summary>The scope an access token from the identity provider must carry.</summary>
    public string Scope { get; init; } = DefaultScope;

    /// <summary>True when the built-in authorization server is on (<c>NO2SQL_OAUTH_BUILTIN=true</c>).</summary>
    public bool Builtin { get; init; }

    /// <summary>The built-in server's data directory: <c>NO2SQL_DATA_DIR</c>, or ~/.no2sql.</summary>
    public string? DataDirectory { get; init; }

    /// <summary><c>NO2SQL_OWNER_PASSWORD</c>, or null for a generated password.</summary>
    public string? OwnerPassword { get; init; }

    /// <summary>Lifetime of the built-in server's access tokens.</summary>
    public TimeSpan AccessTokenLifetime { get; init; } = TimeSpan.FromMinutes(DefaultAccessTokenMinutes);

    public bool HasStaticToken => StaticToken is not null;

    public bool HasAuthority => Authority is not null;

    /// <summary>True when /mcp accepts JWT access tokens (from an external identity provider or the built-in server).</summary>
    public bool UsesJwt => HasAuthority || Builtin;

    /// <summary>The issuer of the accepted JWTs: the external authority, or for the built-in server the public URL's origin.</summary>
    public string? Issuer => Authority ?? (Builtin && PublicUrl is not null ? PublicUrl.GetLeftPart(UriPartial.Authority) : null);

    /// <summary>True when /mcp needs a token.</summary>
    public bool RequiresSignIn => HasStaticToken || UsesJwt;

    /// <summary>The MCP endpoint as clients reach it: the token audience and the metadata's <c>resource</c>.</summary>
    public string? McpUrl => PublicUrl is null ? null : PublicUrl.GetLeftPart(UriPartial.Authority) + HttpServer.McpPath;

    /// <summary>Where the protected resource metadata is published, or null when there is none to publish.</summary>
    public string? ResourceMetadataUrl => UsesJwt && PublicUrl is not null
        ? PublicUrl.GetLeftPart(UriPartial.Authority) + ResourceMetadataPath
        : null;

    /// <summary>Reads and checks the sign-in settings. Error messages name the variable, never its value.</summary>
    /// <param name="getVariable">Reads one environment variable (null when it is not set).</param>
    public static bool TryParse(Func<string, string?> getVariable, out HttpAuthOptions options, out string? error)
    {
        options = None;

        var builtin = Trimmed(getVariable(BuiltinVariable));
        var token = Trimmed(getVariable(TokenVariable));
        var authority = Trimmed(getVariable(AuthorityVariable));
        var publicUrl = Trimmed(getVariable(PublicUrlVariable));
        var scope = Trimmed(getVariable(ScopeVariable));
        var lifetime = Trimmed(getVariable(AccessTokenMinutesVariable));

        // Not trimmed: spaces may be part of a password. Only an empty or all-blank value counts as unset.
        var ownerPassword = getVariable(OwnerPasswordVariable);
        if (string.IsNullOrWhiteSpace(ownerPassword))
        {
            ownerPassword = null;
        }

        var builtinOn = false;
        if (builtin is not null)
        {
            if (string.Equals(builtin, "true", StringComparison.OrdinalIgnoreCase))
            {
                builtinOn = true;
            }
            else if (!string.Equals(builtin, "false", StringComparison.OrdinalIgnoreCase))
            {
                error = $"{BuiltinVariable} must be 'true' or 'false'.";
                return false;
            }
        }

        if (builtinOn && authority is not null)
        {
            error = $"Set {BuiltinVariable} or {AuthorityVariable}, not both: only one authorization server can issue tokens for No2SQL.";
            return false;
        }

        if (!builtinOn && (ownerPassword is not null || lifetime is not null))
        {
            error = $"{(ownerPassword is not null ? OwnerPasswordVariable : AccessTokenMinutesVariable)} only applies together with {BuiltinVariable}=true.";
            return false;
        }

        if (ownerPassword is not null && ownerPassword.Length < MinimumOwnerPasswordLength)
        {
            error = $"{OwnerPasswordVariable} must be at least {MinimumOwnerPasswordLength} characters. Leave it unset to have a strong password generated at the first start.";
            return false;
        }

        var accessTokenMinutes = DefaultAccessTokenMinutes;
        if (lifetime is not null
            && (!int.TryParse(lifetime, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out accessTokenMinutes)
                || accessTokenMinutes is < MinimumAccessTokenMinutes or > MaximumAccessTokenMinutes))
        {
            error = $"{AccessTokenMinutesVariable} must be a whole number of minutes from {MinimumAccessTokenMinutes} to {MaximumAccessTokenMinutes}.";
            return false;
        }

        string? dataDirectory = null;
        if (builtinOn && !TryResolveDataDirectory(getVariable, out dataDirectory, out error))
        {
            return false;
        }

        if (token is not null && !IsUsableToken(token, out error))
        {
            return false;
        }

        Uri? publicUri = null;
        if (publicUrl is not null && !TryParsePublicUrl(publicUrl, out publicUri, out error))
        {
            return false;
        }

        if (authority is not null)
        {
            if (!IsUsableAuthority(authority, out error))
            {
                return false;
            }

            if (publicUri is null)
            {
                error = $"{AuthorityVariable} needs {PublicUrlVariable}, the https:// address clients use to reach No2SQL (tokens must be issued for <{PublicUrlVariable}>{HttpServer.McpPath}).";
                return false;
            }
        }

        if (builtinOn && publicUri is null)
        {
            error = $"{BuiltinVariable}=true needs {PublicUrlVariable}, the https:// address clients use to reach No2SQL. The sign-in pages and token addresses are published under it.";
            return false;
        }

        if (scope is not null)
        {
            if (authority is null)
            {
                error = $"{ScopeVariable} only applies together with {AuthorityVariable}.";
                return false;
            }

            if (!ScopeToken().IsMatch(scope))
            {
                error = $"{ScopeVariable} must be one scope name without spaces or quotes, for example {DefaultScope}.";
                return false;
            }
        }

        options = new HttpAuthOptions
        {
            StaticToken = token,
            Authority = authority,
            PublicUrl = publicUri,
            Scope = scope ?? DefaultScope,
            Builtin = builtinOn,
            DataDirectory = dataDirectory,
            OwnerPassword = ownerPassword,
            AccessTokenLifetime = TimeSpan.FromMinutes(accessTokenMinutes),
        };
        error = null;
        return true;
    }

    // The compiler-generated ToString would print the static token and the owner password. This one only
    // says whether they are set; a property added later is left out until it is added here on purpose.
    private bool PrintMembers(StringBuilder builder)
    {
        builder.Append("StaticToken = ").Append(HasStaticToken ? "[set]" : "[unset]")
            .Append(", Authority = ").Append(Authority)
            .Append(", PublicUrl = ").Append(PublicUrl)
            .Append(", Scope = ").Append(Scope)
            .Append(", Builtin = ").Append(Builtin)
            .Append(", DataDirectory = ").Append(DataDirectory)
            .Append(", OwnerPassword = ").Append(OwnerPassword is null ? "[unset]" : "[set]")
            .Append(", AccessTokenLifetime = ").Append(AccessTokenLifetime);
        return true;
    }

    /// <summary><c>NO2SQL_DATA_DIR</c> (an absolute path), or .no2sql in the home directory.</summary>
    public static bool TryResolveDataDirectory(Func<string, string?> getVariable, out string? directory, out string? error)
    {
        directory = null;
        var configured = Trimmed(getVariable(DataDirectoryVariable));
        if (configured is not null)
        {
            if (!Path.IsPathFullyQualified(configured))
            {
                error = $"{DataDirectoryVariable} must be an absolute path.";
                return false;
            }

            directory = configured;
            error = null;
            return true;
        }

        var home = Trimmed(getVariable(OperatingSystem.IsWindows() ? "USERPROFILE" : "HOME"));
        if (home is null || !Path.IsPathFullyQualified(home))
        {
            error = $"There is no home directory for the default data directory. Set {DataDirectoryVariable} to an absolute path.";
            return false;
        }

        directory = Path.Combine(home, ".no2sql");
        error = null;
        return true;
    }

    private static string? Trimmed(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static bool IsUsableToken(string token, out string? error)
    {
        // Byte length, not characters: the rule is "at least 32 bytes of secret".
        if (Encoding.UTF8.GetByteCount(token) < MinimumTokenLength)
        {
            error = $"{TokenVariable} must be at least {MinimumTokenLength} characters. Generate one with: openssl rand -base64 32";
            return false;
        }

        // RFC 6750 b64token: what a client can put after "Bearer " without quoting.
        if (!BearerToken().IsMatch(token))
        {
            error = $"{TokenVariable} may contain only letters, digits and - . _ ~ + / (and = at the end). Generate one with: openssl rand -base64 32";
            return false;
        }

        if (token.Distinct().Count() < 10 || PlaceholderWords.Any(word => token.Contains(word, StringComparison.OrdinalIgnoreCase)))
        {
            error = $"{TokenVariable} looks like a placeholder, not a random value. Generate one with: openssl rand -base64 32";
            return false;
        }

        error = null;
        return true;
    }

    private static bool IsUsableAuthority(string authority, out string? error)
    {
        // Metadata and signing keys are fetched from here, so only https is accepted, with no exceptions.
        if (!Uri.TryCreate(authority, UriKind.Absolute, out var uri)
            || uri.Scheme != Uri.UriSchemeHttps
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment))
        {
            error = $"{AuthorityVariable} must be the identity provider's issuer, an https:// URL without user name, query or fragment (for example https://login.example.com/).";
            return false;
        }

        error = null;
        return true;
    }

    private static bool TryParsePublicUrl(string value, out Uri? uri, out string? error)
    {
        uri = null;
        if (!Uri.TryCreate(value, UriKind.Absolute, out var parsed)
            || (parsed.Scheme != Uri.UriSchemeHttps && parsed.Scheme != Uri.UriSchemeHttp)
            || !string.IsNullOrEmpty(parsed.UserInfo)
            || !string.IsNullOrEmpty(parsed.Query)
            || !string.IsNullOrEmpty(parsed.Fragment)
            || parsed.AbsolutePath != "/")
        {
            error = $"{PublicUrlVariable} must be the base address clients use, such as https://mcp.example.com, with no path, query or user name. The MCP endpoint is always {HttpServer.McpPath}.";
            return false;
        }

        // Tokens and metadata travel over this address, so plain http is only for this machine.
        if (parsed.Scheme == Uri.UriSchemeHttp && !IsLoopbackHost(parsed))
        {
            error = $"{PublicUrlVariable} must use https:// (plain http:// is accepted only for localhost, 127.0.0.1 or [::1]). Put a TLS-terminating reverse proxy in front of No2SQL.";
            return false;
        }

        uri = parsed;
        error = null;
        return true;
    }

    private static bool IsLoopbackHost(Uri uri) =>
        uri.IsLoopback
        || (IPAddress.TryParse(uri.DnsSafeHost, out var ip) && IPAddress.IsLoopback(ip));

    [GeneratedRegex("^[A-Za-z0-9\\-._~+/]+=*$")]
    private static partial Regex BearerToken();

    // RFC 6749 scope-token: %x21 / %x23-5B / %x5D-7E (printable ASCII without space, " and \).
    [GeneratedRegex("^[\\x21\\x23-\\x5B\\x5D-\\x7E]+$")]
    private static partial Regex ScopeToken();
}
