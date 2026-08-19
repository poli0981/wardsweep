using System.Text.Json;
using System.Text.Json.Serialization;

namespace S3.Ui;

/// <summary>
/// What the UI persists so it can find the broker again after being killed.
/// </summary>
/// <param name="Session">Session GUID naming the pipe.</param>
/// <param name="Database">Where the broker put the job database.</param>
/// <param name="LastSeq">The highest event sequence number this UI has seen.</param>
public sealed record SessionFile(
    [property: JsonPropertyName("session")] string Session,
    [property: JsonPropertyName("database")] string Database,
    [property: JsonPropertyName("last_seq")] ulong LastSeq);

/// <summary>
/// Reads and writes <c>session.json</c>, under the constraint the shipped UI
/// will be held to.
/// </summary>
/// <remarks>
/// <para>
/// <c>ui/WardSweep.UI.Tests/Architecture/UiHasNoDestructiveCodePathTests.cs</c>
/// fails the build if the UI assembly so much as references
/// <c>System.IO.File</c>, <c>Directory</c>, <c>FileInfo</c>,
/// <c>DirectoryInfo</c> or <c>FileSystemInfo</c> — the check reads the
/// assembly's TypeReference table, so a call from inside a method body counts.
/// </para>
/// <para>
/// That rules out <c>File.ReadAllText</c>, <c>File.WriteAllText</c>,
/// <c>File.Exists</c> and <c>Directory.CreateDirectory</c>. This class is
/// written the way the real one will have to be: <see cref="FileStream"/> and
/// the reader/writer types, which are not on the list because they cannot
/// delete anything; existence tested by opening and catching rather than by
/// asking; and the directory created by the broker, never here.
/// </para>
/// </remarks>
public static class Session
{
    /// <summary>
    /// Where the session file lives.
    /// </summary>
    /// <param name="stateDirectory">The spike state directory.</param>
    /// <returns>Full path to <c>session.json</c>.</returns>
    public static string PathIn(string stateDirectory) =>
        Path.Combine(stateDirectory, "session.json");

    /// <summary>
    /// Load the session file.
    /// </summary>
    /// <param name="stateDirectory">The spike state directory.</param>
    /// <returns>The session, or <see langword="null"/> if there is none.</returns>
    public static SessionFile? Load(string stateDirectory)
    {
        try
        {
            using var stream = new FileStream(
                PathIn(stateDirectory),
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream);
            return JsonSerializer.Deserialize<SessionFile>(reader.ReadToEnd());
        }
        catch (FileNotFoundException)
        {
            // "Does it exist?" without System.IO.File. Opening and catching is
            // also the only answer that is not a race.
            return null;
        }
        catch (DirectoryNotFoundException)
        {
            return null;
        }
    }

    /// <summary>
    /// Write the session file.
    /// </summary>
    /// <param name="stateDirectory">The spike state directory, which the broker created.</param>
    /// <param name="session">What to persist.</param>
    public static void Save(string stateDirectory, SessionFile session)
    {
        using var stream = new FileStream(
            PathIn(stateDirectory),
            FileMode.Create,
            FileAccess.Write,
            FileShare.Read);
        using var writer = new StreamWriter(stream);
        writer.Write(JsonSerializer.Serialize(session));
    }
}
