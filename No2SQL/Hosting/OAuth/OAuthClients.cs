using System.Globalization;
using System.Text;

namespace No2SQL.Hosting.OAuth;

/// <summary>A client as the authorization endpoint sees it, from a DCR registration or a fetched metadata document.</summary>
internal sealed record ResolvedClient(string ClientId, bool IsMetadataDocument, string? Name, string? VerifiedHost, IReadOnlyList<string> RedirectUris)
{
    /// <summary>Whether <paramref name="redirectUri"/> is one of this client's, by the matching rule of R5.</summary>
    public bool Allows(string redirectUri) => RedirectUris.Any(registered => RedirectUriRules.Matches(registered, redirectUri));
}

/// <summary>Redirect URI rules for registrations and authorization requests (threat model R5, R10).</summary>
internal static class RedirectUriRules
{
    public const int MaxLength = 2048;
    public const int MaxCount = 10;

    /// <summary>
    /// <c>https://</c> with no fragment and no user info, or plain <c>http://</c> to 127.0.0.1, [::1] or localhost
    /// with any port (RFC 8252 7.3). Custom schemes, wildcards and everything else are refused.
    /// </summary>
    public static bool IsAcceptable(string? value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > MaxLength || value.Contains('#') || value.Contains('*')
            || value.Any(c => char.IsControl(c) || char.IsWhiteSpace(c) || c == '\\')
            || !Uri.TryCreate(value, UriKind.Absolute, out var uri)
            || !string.IsNullOrEmpty(uri.UserInfo)
            || string.IsNullOrEmpty(uri.Host))
        {
            return false;
        }

        return uri.Scheme == Uri.UriSchemeHttps || (uri.Scheme == Uri.UriSchemeHttp && IsLoopbackHost(uri));
    }

    /// <summary>
    /// Exact string equality, except that for a plain-http loopback redirect the port may differ (native apps
    /// pick a free port each time, RFC 8252 7.3).
    /// </summary>
    public static bool Matches(string registered, string presented)
    {
        if (string.Equals(registered, presented, StringComparison.Ordinal))
        {
            return true;
        }

        if (!IsAcceptable(presented)
            || !Uri.TryCreate(registered, UriKind.Absolute, out var a) || !Uri.TryCreate(presented, UriKind.Absolute, out var b)
            || a.Scheme != Uri.UriSchemeHttp || b.Scheme != Uri.UriSchemeHttp || !IsLoopbackHost(a) || !IsLoopbackHost(b))
        {
            return false;
        }

        return string.Equals(a.Host, b.Host, StringComparison.OrdinalIgnoreCase)
            && string.Equals(a.PathAndQuery, b.PathAndQuery, StringComparison.Ordinal);
    }

    /// <summary>What the consent page says the code is sent to: the host, or "an app on your computer" for loopback.</summary>
    public static string Describe(string redirectUri) =>
        Uri.TryCreate(redirectUri, UriKind.Absolute, out var uri)
            ? uri.Scheme == Uri.UriSchemeHttp && IsLoopbackHost(uri) ? "an app on your computer" : uri.IdnHost
            : "an unknown address";

    /// <summary>The origin of a redirect URI (scheme, host and port), for the consent page's form-action.</summary>
    public static string Origin(string redirectUri) => new Uri(redirectUri).GetLeftPart(UriPartial.Authority);

    public static bool IsLoopbackHost(Uri uri) =>
        uri.Host is "127.0.0.1" or "[::1]" || string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase);
}

/// <summary>Cleans a client-supplied name for display (R6): printable characters only, at most 64.</summary>
internal static class ClientNames
{
    public const int MaxLength = 64;

    /// <summary>Drops control, format (such as bidirectional overrides), private-use and unassigned characters and cuts to 64 text elements.</summary>
    public static string? Clean(string? name)
    {
        if (name is null)
        {
            return null;
        }

        var kept = new StringBuilder();
        var elements = StringInfo.GetTextElementEnumerator(name);
        var count = 0;
        while (elements.MoveNext() && count < MaxLength)
        {
            var element = (string)elements.Current;
            var category = CharUnicodeInfo.GetUnicodeCategory(element, 0);
            if (category is UnicodeCategory.Control or UnicodeCategory.Format or UnicodeCategory.PrivateUse or UnicodeCategory.OtherNotAssigned
                or UnicodeCategory.Surrogate or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator)
            {
                continue;
            }

            if (element.Skip(1).Any(c => CharUnicodeInfo.GetUnicodeCategory(c) is UnicodeCategory.Format or UnicodeCategory.Control))
            {
                continue;
            }

            kept.Append(element);
            count++;
        }

        var cleaned = kept.ToString().Trim();
        return cleaned.Length == 0 ? null : cleaned;
    }
}
