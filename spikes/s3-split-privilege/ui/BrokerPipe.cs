using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace S3.Ui;

/// <summary>
/// The client end of the broker pipe, and the framing from
/// <c>docs/08-IPC-PROTOCOL.md</c>.
/// </summary>
public sealed class BrokerPipe : IDisposable
{
    /// <summary>docs/08-IPC-PROTOCOL.md: "Max frame 16 MiB."</summary>
    private const int MaxFrame = 16 * 1024 * 1024;

    private readonly NamedPipeClientStream _stream;
    private int _nextId;

    private BrokerPipe(NamedPipeClientStream stream) => _stream = stream;

    /// <summary>
    /// The pipe name for a session, matching the broker's construction.
    /// </summary>
    /// <param name="session">Session GUID.</param>
    /// <returns>The pipe name, without the <c>\\.\pipe\</c> prefix .NET adds itself.</returns>
    public static string NameFor(string session) => $"wardsweep-s3-{session}";

    /// <summary>
    /// Connect to the broker, retrying while it starts up.
    /// </summary>
    /// <param name="session">Session GUID.</param>
    /// <param name="timeout">How long to keep trying.</param>
    /// <returns>The connected pipe.</returns>
    /// <remarks>
    /// <para>
    /// The retry is not politeness. The UI spawns the broker and the broker
    /// creates the pipe, so there is always a window in which the name does not
    /// exist yet — and with the <c>runas</c> verb that window includes however
    /// long the user takes to answer the UAC prompt, which can be tens of
    /// seconds.
    /// </para>
    /// <para>
    /// <see cref="NamedPipeClientStream.Connect(int)"/> also covers the
    /// <c>ERROR_PIPE_BUSY</c> case by waiting, which is worth knowing: with one
    /// instance configured, a second client does not get an immediate refusal,
    /// it waits for an instance to free up.
    /// </para>
    /// </remarks>
    public static BrokerPipe Connect(string session, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (true)
        {
            var stream = new NamedPipeClientStream(
                ".",
                NameFor(session),
                PipeDirection.InOut,
                PipeOptions.None);
            try
            {
                var remaining = deadline - DateTime.UtcNow;
                stream.Connect((int)Math.Max(200, remaining.TotalMilliseconds));
                stream.ReadMode = PipeTransmissionMode.Message;
                return new BrokerPipe(stream);
            }
            catch (Exception) when (DateTime.UtcNow < deadline)
            {
                stream.Dispose();
                Thread.Sleep(150);
            }
            catch
            {
                stream.Dispose();
                throw;
            }
        }
    }

    /// <summary>
    /// Send a command and return the request id it was sent with.
    /// </summary>
    /// <param name="type">Command name.</param>
    /// <param name="payload">Payload object.</param>
    /// <returns>The request id, which the response echoes.</returns>
    public string Send(string type, object payload)
    {
        var id = $"req-{++_nextId:0000}";
        var envelope = Envelope.Command(id, type, payload);
        var body = JsonSerializer.SerializeToUtf8Bytes(envelope, Envelope.Options);
        if (body.Length > MaxFrame)
        {
            throw new InvalidOperationException($"frame of {body.Length} bytes exceeds the cap");
        }

        var frame = new byte[4 + body.Length];
        BitConverter.TryWriteBytes(frame.AsSpan(0, 4), body.Length);
        body.CopyTo(frame.AsSpan(4));

        _stream.Write(frame, 0, frame.Length);
        _stream.Flush();
        return id;
    }

    /// <summary>
    /// Read one message.
    /// </summary>
    /// <returns>The envelope, or <see langword="null"/> if the broker closed.</returns>
    public Envelope? Receive()
    {
        var message = new MemoryStream();
        var chunk = new byte[64 * 1024];

        do
        {
            int read;
            try
            {
                read = _stream.Read(chunk, 0, chunk.Length);
            }
            catch (IOException)
            {
                // The broker went away. Not an error at this layer: docs/03
                // has the UI fall back to reading job state from SQLite.
                return null;
            }

            if (read == 0)
            {
                return message.Length == 0 ? null : throw new IOException("truncated message");
            }

            message.Write(chunk, 0, read);
            if (message.Length > MaxFrame)
            {
                throw new InvalidOperationException("message exceeds the 16 MiB cap");
            }
        }
        while (!_stream.IsMessageComplete);

        var bytes = message.ToArray();
        if (bytes.Length < 4)
        {
            throw new IOException($"{bytes.Length} byte message cannot hold a length prefix");
        }

        var declared = BitConverter.ToInt32(bytes, 0);
        if (declared != bytes.Length - 4)
        {
            throw new IOException(
                $"length prefix says {declared} bytes, message carried {bytes.Length - 4}");
        }

        return JsonSerializer.Deserialize<Envelope>(
            Encoding.UTF8.GetString(bytes, 4, declared),
            Envelope.Options);
    }

    /// <summary>
    /// Send a command and read until the matching response arrives, handing any
    /// events that arrive first to a callback.
    /// </summary>
    /// <param name="type">Command name.</param>
    /// <param name="payload">Payload object.</param>
    /// <param name="onEvent">Called for each event seen while waiting.</param>
    /// <returns>The response, or <see langword="null"/> if the broker closed.</returns>
    public Envelope? Call(string type, object payload, Action<Envelope>? onEvent = null)
    {
        var id = Send(type, payload);
        while (true)
        {
            var received = Receive();
            if (received is null)
            {
                return null;
            }

            if (received.Id == id)
            {
                return received;
            }

            onEvent?.Invoke(received);
        }
    }

    /// <inheritdoc />
    public void Dispose() => _stream.Dispose();
}
