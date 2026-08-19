using System.ComponentModel;
using System.Diagnostics;

namespace S3.Ui;

/// <summary>
/// Spike S3 stand-in for the WardSweep UI.
/// </summary>
/// <remarks>
/// <para>
/// Each scenario is one leg of the six acceptance criteria in
/// <c>docs/13-P0-SPIKES.md</c>. The elevation scenarios spawn the broker
/// themselves, because who spawns it is precisely what decides whether a UAC
/// prompt appears; the rest connect to a broker the harness owns, so the
/// harness can capture its output and kill it on cue.
/// </para>
/// <para>
/// Every machine-readable line is <c>S3|key=value|…</c> on stdout, the same
/// convention the broker uses, so one transcript carries both halves.
/// </para>
/// </remarks>
public static class Program
{
    /// <summary>Entry point.</summary>
    /// <param name="args">Scenario name followed by <c>--key value</c> pairs.</param>
    /// <returns>0 on success, 1 on a scenario failure, 2 on a usage error.</returns>
    public static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.Error.WriteLine(
                "usage: S3.Ui <spawn-audit|spawn-apply|hello|stream|resume|read-state|shutdown|duplex-client> [--key value]");
            return 2;
        }

        var options = Parse(args.Skip(1));
        try
        {
            return args[0] switch
            {
                "spawn-audit" => SpawnAudit(options),
                "spawn-apply" => SpawnApply(options),
                "hello" => Hello(options),
                "stream" => Stream(options),
                "resume" => Resume(options),
                "read-state" => ReadState(options),
                "shutdown" => Shutdown(options),
                "duplex-client" => DuplexClient(options),
                var unknown => Usage(unknown),
            };
        }
        catch (Exception error)
        {
            Fact($"fatal|scenario={args[0]}|error={OneLine(error.Message)}");
            Console.Error.WriteLine(error);
            return 1;
        }
    }

    private static int Usage(string scenario)
    {
        Console.Error.WriteLine($"unknown scenario: {scenario}");
        return 2;
    }

    // -----------------------------------------------------------------------
    // Criterion 1 — unelevated audit, no UAC prompt
    // -----------------------------------------------------------------------

    private static int SpawnAudit(Options options)
    {
        // UseShellExecute = false and no verb. This is the shape that must not
        // prompt: same integrity level as this process, which is medium.
        var start = new ProcessStartInfo(options.Broker)
        {
            UseShellExecute = false,
        };
        AddBrokerArguments(start, options);

        using var broker = Process.Start(start)
            ?? throw new InvalidOperationException("the broker did not start");
        Fact($"spawn|mode=unelevated|verb=none|pid={broker.Id}");

        using var pipe = BrokerPipe.Connect(options.Session, TimeSpan.FromSeconds(20));
        var ack = SayHello(pipe, options, resumeFrom: 0)
            ?? throw new InvalidOperationException("no HelloAck");

        var elevated = ack.Bool("elevated") ?? true;
        Fact($"audit|elevated={elevated.ToString().ToLowerInvariant()}");

        var findings = 0;
        var complete = pipe.Call("ScanStart", new { mode = "audit", deep_fs = false }, received =>
        {
            if (received.Type == "ScanBatch")
            {
                findings += (int)(received.Number("scanned_count") ?? 0);
            }
        });

        // The Ack arrives first; the batches and ScanComplete follow it.
        if (complete is not null)
        {
            while (true)
            {
                var received = pipe.Receive();
                if (received is null || received.Type == "ScanComplete")
                {
                    Fact($"audit|scan_complete={received is not null}|total={received?.Number("total") ?? 0}");
                    break;
                }
            }
        }

        pipe.Send("Shutdown", new { });
        broker.WaitForExit(10_000);
        Fact($"audit|broker_exited={broker.HasExited}");
        return elevated ? 1 : 0;
    }

    // -----------------------------------------------------------------------
    // Criterion 2 — one prompt, at apply
    // -----------------------------------------------------------------------

    private static int SpawnApply(Options options)
    {
        // The runas verb requires UseShellExecute = true, and that forecloses
        // stdio redirection and handle inheritance outright. The pipe is
        // therefore not merely the preferred channel to an elevated broker, it
        // is the only one available — which is worth knowing before designing
        // around a redirected stream.
        var start = new ProcessStartInfo(options.Broker)
        {
            UseShellExecute = true,
            Verb = "runas",
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        AddBrokerArguments(start, options);

        Process? broker;
        try
        {
            broker = Process.Start(start);
        }
        catch (Win32Exception error) when (error.NativeErrorCode == 1223)
        {
            // ERROR_CANCELLED. docs/03-ARCHITECTURE.md failure model: "UAC
            // declined → Job never starts; nothing was written."
            Fact("spawn|mode=elevated|verb=runas|result=uac_declined");
            return 0;
        }

        if (broker is null)
        {
            Fact("spawn|mode=elevated|verb=runas|result=no_process");
            return 1;
        }

        using (broker)
        {
            Fact($"spawn|mode=elevated|verb=runas|pid={broker.Id}");

            using var pipe = BrokerPipe.Connect(options.Session, TimeSpan.FromSeconds(120));
            var ack = SayHello(pipe, options, resumeFrom: 0)
                ?? throw new InvalidOperationException("no HelloAck");

            var elevated = ack.Bool("elevated") ?? false;
            Fact($"apply|elevated={elevated.ToString().ToLowerInvariant()}");

            var last = RunJob(pipe, options, ack, stopAfter: null);
            Fact($"apply|last_seq={last}");

            pipe.Send("Shutdown", new { });
            broker.WaitForExit(10_000);
            return elevated ? 0 : 1;
        }
    }

    // -----------------------------------------------------------------------
    // Connect-only scenarios, against a broker the harness owns
    // -----------------------------------------------------------------------

    private static int Hello(Options options)
    {
        using var pipe = BrokerPipe.Connect(options.Session, TimeSpan.FromSeconds(20));
        var ack = SayHello(pipe, options, resumeFrom: 0);
        if (ack is null)
        {
            Fact("hello|result=refused");
            return 1;
        }

        Fact($"hello|result=ok|elevated={(ack.Bool("elevated") ?? false).ToString().ToLowerInvariant()}"
            + $"|broker_version={ack.String("broker_version")}"
            + $"|protocol={ack.Number("protocol")}"
            + $"|database={ack.String("database")}");
        return 0;
    }

    /// <summary>
    /// Start or join the job and print every event, optionally dying part-way.
    /// </summary>
    private static int Stream(Options options)
    {
        using var pipe = BrokerPipe.Connect(options.Session, TimeSpan.FromSeconds(20));
        var persisted = Session.Load(options.StateDirectory)?.LastSeq ?? 0;
        var ack = SayHello(pipe, options, persisted)
            ?? throw new InvalidOperationException("no HelloAck");

        var last = RunJob(pipe, options, ack, options.StopAfter);
        Fact($"stream|last_seq={last}");
        return 0;
    }

    private static int Resume(Options options)
    {
        using var pipe = BrokerPipe.Connect(options.Session, TimeSpan.FromSeconds(20));
        var persisted = Session.Load(options.StateDirectory)?.LastSeq ?? 0;
        Fact($"resume|persisted_last_seq={persisted}");

        var ack = SayHello(pipe, options, persisted)
            ?? throw new InvalidOperationException("no HelloAck");
        Fact($"resume|broker_last_seq={ack.Number("job_last_seq") ?? 0}"
            + $"|job_finished={(ack.Bool("job_finished") ?? false).ToString().ToLowerInvariant()}");

        var last = RunJob(pipe, options, ack, options.StopAfter);
        Fact($"resume|last_seq={last}");
        return 0;
    }

    private static int ReadState(Options options)
    {
        var session = Session.Load(options.StateDirectory);
        var database = options.Database
            ?? session?.Database
            ?? Path.Combine(options.StateDirectory, "jobs.db");

        try
        {
            var state = JobStateReader.Read(database);
            Fact($"read-state|result=ok|job_id={state.JobId}|status={state.Status}"
                + $"|last_seq={state.LastSeq}|stages_completed={state.StagesCompleted}");
            return 0;
        }
        catch (Exception error)
        {
            // Reported, never swallowed: whether a read-only open survives a
            // force-killed writer is the whole of criterion 6.
            Fact($"read-state|result=failed|error={OneLine(error.Message)}");
            return 1;
        }
    }

    private static int Shutdown(Options options)
    {
        using var pipe = BrokerPipe.Connect(options.Session, TimeSpan.FromSeconds(20));
        _ = SayHello(pipe, options, resumeFrom: 0);
        pipe.Send("Shutdown", new { });
        Fact("shutdown|sent=true");
        return 0;
    }

    /// <summary>
    /// Connect, then deliberately send nothing, so the broker's duplex probe can
    /// time a write against a read that cannot complete.
    /// </summary>
    private static int DuplexClient(Options options)
    {
        using var pipe = BrokerPipe.Connect(options.Session, TimeSpan.FromSeconds(20));
        Fact("duplex-client|connected=true");
        Thread.Sleep(3000);
        pipe.Send("Hello", new { ui_version = "spike", session = options.Session });
        Fact("duplex-client|sent=true");
        Thread.Sleep(500);
        return 0;
    }

    // -----------------------------------------------------------------------
    // Shared
    // -----------------------------------------------------------------------

    private static Envelope? SayHello(BrokerPipe pipe, Options options, ulong resumeFrom)
    {
        var ack = pipe.Call("Hello", new
        {
            ui_version = "spike-s3",
            session = options.Session,
            resume_from = resumeFrom,
        });

        if (ack is not null && ack.Type == "HelloAck")
        {
            // Only now: the broker created the state directory, so writing into
            // it cannot fail, and the UI never needs System.IO.Directory.
            Session.Save(options.StateDirectory, new SessionFile(
                options.Session,
                ack.String("database") ?? Path.Combine(options.StateDirectory, "jobs.db"),
                resumeFrom));
        }

        return ack;
    }

    /// <summary>
    /// Drive the job to completion, or until <paramref name="stopAfter"/> events
    /// have arrived, printing each one.
    /// </summary>
    /// <remarks>
    /// The session file is rewritten after every event so a hard kill leaves an
    /// exact resume point. That is deliberate for measurement and wrong for
    /// production: at the <c>ScanBatch</c> rates in
    /// <c>docs/10-PERF-BUDGET.md</c> it would be a write per batch. The real UI
    /// should persist the session GUID only and recover its position from the
    /// <c>JobState</c> snapshot the broker sends on reconnect.
    /// </remarks>
    private static ulong RunJob(BrokerPipe pipe, Options options, Envelope ack, int? stopAfter)
    {
        var existing = ack.String("job_id");
        var from = ack.Number("resumed_from") ?? 0;

        if (string.IsNullOrEmpty(existing))
        {
            pipe.Call("ApplyPlan", new { plan_id = "synthetic", approved_artifact_ids = Array.Empty<string>() });
            Fact("job|started=true");
        }
        else
        {
            pipe.Call("JobResume", new { job_id = existing, from_seq = from });
            Fact($"job|resumed=true|job_id={existing}|from_seq={from}");
        }

        var last = from;
        var seen = 0;

        while (true)
        {
            var received = pipe.Receive();
            if (received is null)
            {
                Fact($"job|broker_gone=true|last_seq={last}");
                return last;
            }

            if (received.Seq is { } seq)
            {
                last = seq;
                Fact($"event|seq={seq}|type={received.Type}|key={received.String("message_key") ?? received.Type}");
                Session.Save(options.StateDirectory, new SessionFile(
                    options.Session,
                    ack.String("database") ?? Path.Combine(options.StateDirectory, "jobs.db"),
                    last));
                seen++;
            }

            if (received.Type == "JobComplete")
            {
                Fact($"job|complete=true|last_seq={last}");
                return last;
            }

            if (stopAfter is { } limit && seen >= limit)
            {
                // Die without unwinding. A cooperative shutdown would let the
                // broker see a clean close, and the case under test is the one
                // where it does not.
                Fact($"job|abandoning=true|at_seq={last}");
                Console.Out.Flush();
                Environment.Exit(0);
            }
        }
    }

    private static void AddBrokerArguments(ProcessStartInfo start, Options options)
    {
        start.ArgumentList.Add("--session");
        start.ArgumentList.Add(options.Session);
        start.ArgumentList.Add("--state-dir");
        start.ArgumentList.Add(options.StateDirectory);
        start.ArgumentList.Add("--expect-client");
        start.ArgumentList.Add("S3.Ui.exe");
        if (options.FactFile is { } factFile)
        {
            start.ArgumentList.Add("--fact-file");
            start.ArgumentList.Add(factFile);
        }
        if (options.JournalMode is { } journal)
        {
            start.ArgumentList.Add("--journal-mode");
            start.ArgumentList.Add(journal);
        }
    }

    private sealed record Options(
        string Session,
        string StateDirectory,
        string Broker,
        string? Database,
        string? FactFile,
        string? JournalMode,
        int? StopAfter);

    private static Options Parse(IEnumerable<string> args)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        string? key = null;
        foreach (var argument in args)
        {
            if (argument.StartsWith("--", StringComparison.Ordinal))
            {
                key = argument[2..];
                values[key] = "true";
            }
            else if (key is not null)
            {
                values[key] = argument;
                key = null;
            }
        }

        var stateDirectory = values.GetValueOrDefault("state-dir")
            ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "WardSweep",
                "spike-s3");

        return new Options(
            values.GetValueOrDefault("session") ?? "no-session",
            stateDirectory,
            values.GetValueOrDefault("broker") ?? "s3-broker.exe",
            values.GetValueOrDefault("database"),
            values.GetValueOrDefault("fact-file"),
            values.GetValueOrDefault("journal-mode"),
            int.TryParse(values.GetValueOrDefault("stop-after"), out var stop) ? stop : null);
    }

    private static void Fact(string line)
    {
        Console.Out.WriteLine($"S3|{line}");
        Console.Out.Flush();
    }

    private static string OneLine(string value) =>
        value.Replace('\r', ' ').Replace('\n', ' ').Replace('|', ' ');
}
