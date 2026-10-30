namespace WardSweep.UI.Services;

/// <summary>
/// The UI's only route to the broker.
/// </summary>
/// <remarks>
/// <para>
/// The command surface is closed by design (docs/08-IPC-PROTOCOL.md): there is
/// no DeletePath, no DeleteKey, no StopService. Destructive commands will name
/// artifact ids from a plan the broker built and holds in memory, so a
/// compromised UI cannot express "delete C:\Windows" — the vocabulary does not
/// contain it.
/// </para>
/// <para>
/// Only <c>Hello</c> exists in this build. Spike S3 passed
/// (spikes/S3-RESULT.md); the rest of the protocol arrives with the broker.
/// </para>
/// </remarks>
public interface IBrokerClient
{
    /// <summary>
    /// Handshake with the broker.
    /// </summary>
    /// <param name="cancellationToken">Cancels the handshake.</param>
    /// <returns>What the broker reports about itself.</returns>
    Task<BrokerInfo> HelloAsync(CancellationToken cancellationToken);
}
