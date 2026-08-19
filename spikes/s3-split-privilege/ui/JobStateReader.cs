using Microsoft.Data.Sqlite;

namespace S3.Ui;

/// <summary>
/// Reads job state out of the broker's database without the broker.
/// </summary>
/// <remarks>
/// <para>
/// S3 criterion 6, and the failure model in <c>docs/03-ARCHITECTURE.md</c>: "If
/// the broker is gone instead, the UI reads job state directly from SQLite in
/// read-only mode and offers resume or rollback."
/// </para>
/// <para>
/// <c>Mode=ReadOnly</c> is the point of the exercise, not an optimisation. A
/// writer that was force-killed can leave a hot rollback journal or a
/// <c>-wal</c>/<c>-shm</c> pair, and SQLite must write to recover either — so a
/// genuinely read-only open of a database in that state can fail outright
/// rather than return stale data. Whether it does is what the spike measures,
/// which is why the failure is reported rather than swallowed.
/// </para>
/// </remarks>
public static class JobStateReader
{
    /// <summary>What the database says about a job.</summary>
    /// <param name="JobId">Job identifier.</param>
    /// <param name="Status">Job status as last committed.</param>
    /// <param name="LastSeq">Event sequence number at the last committed stage.</param>
    /// <param name="StagesCompleted">How many stages have an end timestamp.</param>
    public sealed record JobState(string JobId, string Status, long LastSeq, int StagesCompleted);

    /// <summary>
    /// Open the database read-only and read the single job row.
    /// </summary>
    /// <param name="databasePath">Path to the broker's database.</param>
    /// <returns>The job state.</returns>
    /// <exception cref="SqliteException">
    /// If the database cannot be opened read-only — which is a finding, not a
    /// bug, and must not be caught here.
    /// </exception>
    public static JobState Read(string databasePath)
    {
        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadOnly,
            // Without this, a second reader while the writer lives can trip over
            // the shared cache. The UI is the only reader, but saying so
            // explicitly keeps the measurement about journal state and nothing else.
            Cache = SqliteCacheMode.Private,
        }.ToString();

        using var connection = new SqliteConnection(connectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT j.id,
                   j.status,
                   j.last_seq,
                   (SELECT COUNT(*) FROM job_stages s
                     WHERE s.job_id = j.id AND s.ended_utc IS NOT NULL)
              FROM jobs j
             ORDER BY j.created_utc DESC
             LIMIT 1
            """;

        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            throw new InvalidOperationException("the database holds no job row");
        }

        return new JobState(
            reader.GetString(0),
            reader.GetString(1),
            reader.GetInt64(2),
            reader.GetInt32(3));
    }
}
