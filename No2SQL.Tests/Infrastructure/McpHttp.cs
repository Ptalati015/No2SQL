using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace No2SQL.Tests.Infrastructure;

/// <summary>One answer from the MCP endpoint: the HTTP response and the JSON-RPC message in it, if any.</summary>
public sealed record McpReply(HttpResponseMessage Http, JsonNode? Message)
{
    public JsonNode Result => Message?["result"]
        ?? throw new InvalidOperationException($"No JSON-RPC result. HTTP {(int)Http.StatusCode}, message: {Message?.ToJsonString() ?? "(none)"}");

    public JsonNode? Error => Message?["error"];
}

/// <summary>
/// Sends JSON-RPC requests to /mcp the way a Streamable HTTP client does, without an MCP client
/// library in between, so tests can see and set every header and status code.
/// </summary>
public static class McpHttp
{
    public const string ProtocolVersion = "2025-06-18";

    private static int _nextId;

    public static Task<McpReply> InitializeAsync(this HttpClient client, CancellationToken cancellationToken = default) =>
        client.RpcAsync("initialize", new JsonObject
        {
            ["protocolVersion"] = ProtocolVersion,
            ["capabilities"] = new JsonObject(),
            ["clientInfo"] = new JsonObject { ["name"] = "no2sql-tests", ["version"] = "0" },
        }, cancellationToken: cancellationToken);

    public static Task<McpReply> ListToolsAsync(this HttpClient client, CancellationToken cancellationToken = default) =>
        client.RpcAsync("tools/list", cancellationToken: cancellationToken);

    public static Task<McpReply> CallToolAsync(this HttpClient client, string name, JsonObject? arguments = null, CancellationToken cancellationToken = default) =>
        client.RpcAsync("tools/call", new JsonObject { ["name"] = name, ["arguments"] = arguments ?? new JsonObject() }, cancellationToken: cancellationToken);

    /// <summary>POSTs one JSON-RPC request to /mcp and reads the answer (plain JSON or a one-message event stream).</summary>
    /// <param name="configure">Changes the HTTP request before it is sent, for example to add or remove a header.</param>
    public static async Task<McpReply> RpcAsync(
        this HttpClient client,
        string method,
        JsonObject? parameters = null,
        Action<HttpRequestMessage>? configure = null,
        CancellationToken cancellationToken = default)
    {
        var id = Interlocked.Increment(ref _nextId);
        var body = new JsonObject { ["jsonrpc"] = "2.0", ["id"] = id, ["method"] = method };
        if (parameters is not null)
        {
            body["params"] = parameters;
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, "/mcp")
        {
            Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"),
        };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
        if (method != "initialize")
        {
            request.Headers.Add("MCP-Protocol-Version", ProtocolVersion);
        }

        configure?.Invoke(request);

        var response = await client.SendAsync(request, cancellationToken);
        var text = await response.Content.ReadAsStringAsync(cancellationToken);
        return new McpReply(response, FindMessage(response, text, id));
    }

    private static JsonNode? FindMessage(HttpResponseMessage response, string text, int id)
    {
        if (response.Content.Headers.ContentType?.MediaType == "text/event-stream")
        {
            foreach (var line in text.Split('\n'))
            {
                if (line.StartsWith("data:", StringComparison.Ordinal)
                    && JsonNode.Parse(line[5..]) is { } message
                    && message["id"]?.GetValueKind() == JsonValueKind.Number
                    && message["id"]!.GetValue<int>() == id)
                {
                    return message;
                }
            }

            return null;
        }

        return string.IsNullOrWhiteSpace(text) ? null : JsonNode.Parse(text);
    }
}
