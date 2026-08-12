namespace WardSweep.UI.Services;

/// <summary>
/// An in-memory <see cref="IBrokerClient"/> for design time and tests.
/// </summary>
/// <remarks>
/// Required by docs/09-UI-SPEC.md so that view models can be exercised without
/// a broker process. It is also what makes the architecture tests meaningful:
/// the UI assembly can be fully driven without any code that touches the
/// filesystem or the registry.
/// </remarks>
public sealed class FakeBrokerClient : IBrokerClient
{
    /// <summary>
    /// Gets or sets the handshake result this fake returns.
    /// </summary>
    public BrokerInfo Info { get; set; } =
        new("0.0.1", "0.0.1", CatalogSignatureValid: true, Elevated: false);

    /// <inheritdoc />
    public Task<BrokerInfo> HelloAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(Info);
    }
}
