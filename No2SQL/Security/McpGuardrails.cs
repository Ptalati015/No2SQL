using System.Text.RegularExpressions;
using No2SQL.Sql.Models;

namespace No2SQL.Security;

internal sealed class McpGuardrails
{
    private readonly HashSet<string> _blockedSystemDatabases = new(StringComparer.OrdinalIgnoreCase)
    {
        "admin",
        "config",
        "local"
    };

    private readonly HashSet<string> _allowedDatabases;

    public bool BlockSystemDatabases { get; }

    public McpGuardrails()
    {
        BlockSystemDatabases = ReadBoolEnv("NO2SQL_BLOCK_SYSTEM_DATABASES", defaultValue: true);

        _allowedDatabases = ParseCsvEnv("NO2SQL_ALLOWED_DATABASES");
    }

    public string ValidateDatabaseName(string? databaseName)
    {
        var normalized = ValidateIdentifier(databaseName, "databaseName", 128);

        if (BlockSystemDatabases && _blockedSystemDatabases.Contains(normalized))
        {
            throw new ArgumentException($"Database '{normalized}' is blocked by policy.", nameof(databaseName));
        }

        if (_allowedDatabases.Count > 0 && !_allowedDatabases.Contains(normalized))
        {
            throw new ArgumentException($"Database '{normalized}' is not in NO2SQL_ALLOWED_DATABASES.", nameof(databaseName));
        }

        return normalized;
    }

    public string ValidateCollectionName(string? collectionName)
    {
        return ValidateIdentifier(collectionName, "collectionName", 128);
    }

    public string ValidateSource(string? source)
    {
        if (string.IsNullOrWhiteSpace(source))
        {
            return "sql";
        }

        var normalized = source.Trim().ToLowerInvariant();
        return normalized switch
        {
            "sql" => normalized,
            "mongo" => normalized,
            "auto" => normalized,
            _ => throw new ArgumentException("Invalid source. Allowed values: sql, mongo, auto.", nameof(source))
        };
    }

    public List<UserRelationshipOverride>? ValidateOverrides(List<UserRelationshipOverride>? overrides)
    {
        if (overrides == null)
        {
            return null;
        }

        foreach (var item in overrides)
        {
            _ = ValidateIdentifier(item.FromCollection, "fromCollection", 128);
            _ = ValidateIdentifier(item.FromField, "fromField", 128);
            _ = ValidateIdentifier(item.ToCollection, "toCollection", 128);
            _ = ValidateIdentifier(item.ToField, "toField", 128);
        }

        return overrides;
    }

    private static string ValidateIdentifier(string? value, string fieldName, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException($"{fieldName} cannot be null or empty.", fieldName);
        }

        var candidate = value.Trim();
        if (candidate.Length > maxLength)
        {
            throw new ArgumentException($"{fieldName} exceeds maximum length of {maxLength}.", fieldName);
        }

        if (ContainsPromptInjectionMarkers(candidate))
        {
            throw new ArgumentException($"{fieldName} contains disallowed meta-instruction content.", fieldName);
        }

        if (!Regex.IsMatch(candidate, @"^[A-Za-z0-9_.$-]+$"))
        {
            throw new ArgumentException(
                $"{fieldName} contains unsupported characters. Allowed characters: letters, numbers, _, ., $, -",
                fieldName);
        }

        return candidate;
    }

    private static bool ContainsPromptInjectionMarkers(string input)
    {
        return Regex.IsMatch(
            input,
            @"(ignore[_\s]+previous|system[_\s]+prompt|developer[_\s]+message|tool[_\s]*call|function[_\s]*call|jailbreak|bypass|exfiltrat|token|credential|secret)",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }

    private static bool ReadBoolEnv(string key, bool defaultValue)
    {
        var raw = Environment.GetEnvironmentVariable(key);
        return bool.TryParse(raw, out var parsed) ? parsed : defaultValue;
    }

    private static HashSet<string> ParseCsvEnv(string key)
    {
        var raw = Environment.GetEnvironmentVariable(key);
        if (string.IsNullOrWhiteSpace(raw))
        {
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }

        return raw
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(item => !string.IsNullOrWhiteSpace(item))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
    }
}