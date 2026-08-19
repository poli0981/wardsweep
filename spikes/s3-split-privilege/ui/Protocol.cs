using System.Text.Json;
using System.Text.Json.Serialization;

namespace S3.Ui;

/// <summary>
/// One message on the wire, matching <c>docs/08-IPC-PROTOCOL.md</c>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Seq"/> is the amendment this spike proposes. The document
/// requires a reconnecting UI to resume the event stream, but gives events no
/// sequence number and <c>Hello</c> no resume point, so the reconnecting client
/// has no way to say where it got to. Without it the requirement cannot be
/// implemented, only approximated.
/// </para>
/// </remarks>
public sealed class Envelope
{
    [JsonPropertyName("v")]
    public int Version { get; set; } = 1;

    [JsonPropertyName("id")]
    public string? Id { get; set; }

    [JsonPropertyName("type")]
    public string Type { get; set; } = string.Empty;

    [JsonPropertyName("seq")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ulong? Seq { get; set; }

    [JsonPropertyName("payload")]
    public JsonElement Payload { get; set; }

    public static readonly JsonSerializerOptions Options = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>
    /// Build a command envelope with an inline payload object.
    /// </summary>
    /// <param name="id">Request id the response will echo.</param>
    /// <param name="type">Command name.</param>
    /// <param name="payload">Anonymous object serialised as the payload.</param>
    /// <returns>The envelope.</returns>
    public static Envelope Command(string id, string type, object payload)
    {
        // Round-tripping through JsonDocument keeps Payload a JsonElement, so
        // one type serves both directions and there is no separate request DTO
        // per command.
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(payload, Options));
        return new Envelope
        {
            Id = id,
            Type = type,
            Payload = document.RootElement.Clone(),
        };
    }

    /// <summary>
    /// Read a string field out of the payload.
    /// </summary>
    /// <param name="name">Field name.</param>
    /// <returns>The value, or <see langword="null"/> if absent.</returns>
    public string? String(string name) =>
        Payload.ValueKind == JsonValueKind.Object
        && Payload.TryGetProperty(name, out var value)
        && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    /// <summary>
    /// Read a boolean field out of the payload.
    /// </summary>
    /// <param name="name">Field name.</param>
    /// <returns>The value, or <see langword="null"/> if absent.</returns>
    public bool? Bool(string name) =>
        Payload.ValueKind == JsonValueKind.Object
        && Payload.TryGetProperty(name, out var value)
        && (value.ValueKind == JsonValueKind.True || value.ValueKind == JsonValueKind.False)
            ? value.GetBoolean()
            : null;

    /// <summary>
    /// Read an unsigned integer field out of the payload.
    /// </summary>
    /// <param name="name">Field name.</param>
    /// <returns>The value, or <see langword="null"/> if absent.</returns>
    public ulong? Number(string name) =>
        Payload.ValueKind == JsonValueKind.Object
        && Payload.TryGetProperty(name, out var value)
        && value.ValueKind == JsonValueKind.Number
            ? value.GetUInt64()
            : null;
}
