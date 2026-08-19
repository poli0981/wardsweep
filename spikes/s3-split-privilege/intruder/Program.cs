using System.Diagnostics;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace S3.Intruder;

/// <summary>
/// A process that is not the UI, trying to talk to the broker.
/// </summary>
/// <remarks>
/// <para>
/// It runs as the same user as the UI, so the pipe DACL admits it — that is the
/// point. <c>docs/08-IPC-PROTOCOL.md</c> grants "SYSTEM and Administrators full
/// control, plus the launching user's SID", and every process that user starts
/// carries that SID. The DACL keeps out other users and remote clients; it does
/// nothing about a hostile process on the same desktop. What stops this one is
/// the client image check, and separating the two mechanisms is why the spike
/// has an intruder at all.
/// </para>
/// <para>
/// Two modes:
/// </para>
/// <list type="bullet">
///   <item><c>connect</c> — connect while the pipe is free and expect the broker
///   to refuse on image mismatch.</item>
///   <item><c>second</c> — connect while the UI holds the single instance, and
///   report what actually happens. <c>docs/08</c> says a second client is
///   "refused, not queued"; this measures whether that is true at the transport
///   layer or only at the application layer.</item>
/// </list>
/// </remarks>
public static class Program
{
    /// <summary>Entry point.</summary>
    /// <param name="args">Mode, then the session GUID.</param>
    /// <returns>0 always — a refusal is the expected outcome, not a failure.</returns>
    public static int Main(string[] args)
    {
        var mode = args.Length > 0 ? args[0] : "connect";
        var session = args.Length > 1 ? args[1] : "no-session";
        var timeout = args.Length > 2 && int.TryParse(args[2], out var parsed) ? parsed : 3000;

        var stopwatch = Stopwatch.StartNew();
        var stream = new NamedPipeClientStream(
            ".",
            $"wardsweep-s3-{session}",
            PipeDirection.InOut,
            PipeOptions.None);
        try
        {
            stream.Connect(timeout);
        }
        catch (TimeoutException)
        {
            // With nMaxInstances = 1 and the UI attached, this is what "a second
            // client" actually experiences: WaitNamedPipe waits for a free
            // instance and eventually times out. It is not an immediate refusal.
            Fact($"intruder|mode={mode}|result=timed_out|waited_ms={stopwatch.ElapsedMilliseconds}");
            return 0;
        }
        catch (Exception error)
        {
            Fact($"intruder|mode={mode}|result=connect_failed|error={OneLine(error.Message)}"
                + $"|waited_ms={stopwatch.ElapsedMilliseconds}");
            return 0;
        }

        using (stream)
        {
            Fact($"intruder|mode={mode}|result=connected|waited_ms={stopwatch.ElapsedMilliseconds}");

            try
            {
                stream.ReadMode = PipeTransmissionMode.Message;
            }
            catch (IOException error)
            {
                // The connect succeeded — the DACL admitted this process, as
                // expected — and the broker then hung up on the image check
                // before a single byte was exchanged. Reported separately from
                // a connect failure, because the two say opposite things about
                // which mechanism did the work.
                Fact($"intruder|mode={mode}|refused_after_connect=true|error={OneLine(error.Message)}");
                return 0;
            }

            // Say something well-formed. If the broker answers, the image check
            // did not stop it, and that is the finding.
            var body = JsonSerializer.SerializeToUtf8Bytes(new
            {
                v = 1,
                id = "req-0001",
                type = "Hello",
                payload = new { ui_version = "intruder", session },
            });
            var frame = new byte[4 + body.Length];
            BitConverter.TryWriteBytes(frame.AsSpan(0, 4), body.Length);
            body.CopyTo(frame.AsSpan(4));

            try
            {
                stream.Write(frame, 0, frame.Length);
                stream.Flush();
            }
            catch (IOException error)
            {
                Fact($"intruder|mode={mode}|hello=write_failed|error={OneLine(error.Message)}");
                return 0;
            }

            var buffer = new byte[64 * 1024];
            try
            {
                var read = stream.Read(buffer, 0, buffer.Length);
                if (read == 0)
                {
                    Fact($"intruder|mode={mode}|hello=closed_without_reply");
                    return 0;
                }

                var reply = Encoding.UTF8.GetString(buffer, 4, Math.Max(0, read - 4));
                Fact($"intruder|mode={mode}|hello=answered|reply={OneLine(reply)}");
            }
            catch (IOException)
            {
                // The broker disconnected the instance. Expected: it refused
                // before reading a single command.
                Fact($"intruder|mode={mode}|hello=disconnected_by_broker");
            }

            return 0;
        }
    }

    private static void Fact(string line)
    {
        Console.Out.WriteLine($"S3|{line}");
        Console.Out.Flush();
    }

    private static string OneLine(string value) =>
        value.Replace('\r', ' ').Replace('\n', ' ').Replace('|', ' ');
}
