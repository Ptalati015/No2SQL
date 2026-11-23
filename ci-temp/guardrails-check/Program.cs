// TEMPORARY (BL-3 evidence): same matrix as TestDatabaseVisibility in No2SQL.Test. Exits 1 on any mismatch.
using No2SQL.Security;

var databases = new[] { "admin", "Config", "LOCAL", "sales", "inventory" };
var failures = 0;

void Check(string label, string? block, string? allowed, string[] expected)
{
    Environment.SetEnvironmentVariable("NO2SQL_BLOCK_SYSTEM_DATABASES", block);
    Environment.SetEnvironmentVariable("NO2SQL_ALLOWED_DATABASES", allowed);

    var visible = new McpGuardrails().FilterVisibleDatabases(databases);
    var passed = visible.SequenceEqual(expected);
    if (!passed) failures++;
    Console.WriteLine($"{(passed ? "PASS" : "FAIL")} {label}: block={block ?? "(unset)"} allow={allowed ?? "(unset)"} -> [{string.Join(", ", visible)}]");
}

Check("Default hides system databases", null, null, new[] { "sales", "inventory" });
Check("Block=true hides system databases", "true", null, new[] { "sales", "inventory" });
Check("Block=false lists system databases", "false", null, databases);
Check("Block on, allow-list set", "true", "sales", new[] { "sales" });
Check("Block off, allow-list set", "false", "inventory", new[] { "inventory" });
Check("Block on wins over allow-list naming admin", null, "sales,admin", new[] { "sales" });
Check("Block off, allow-list naming admin", "false", " SALES , admin ", new[] { "admin", "sales" });

Console.WriteLine(failures == 0 ? "All visibility checks passed" : $"{failures} visibility check(s) failed");
return failures == 0 ? 0 : 1;
