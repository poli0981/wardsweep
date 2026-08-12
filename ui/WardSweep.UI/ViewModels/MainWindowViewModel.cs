using CommunityToolkit.Mvvm.ComponentModel;
using WardSweep.UI.Resources;
using WardSweep.UI.Services;

namespace WardSweep.UI.ViewModels;

/// <summary>
/// View model for the shell window.
/// </summary>
/// <remarks>
/// <para>
/// No view model in this assembly may touch the filesystem or the registry.
/// docs/09-UI-SPEC.md puts it plainly: the UI process has no destructive code
/// path at all. An architecture test in WardSweep.UI.Tests enforces this rather
/// than trusting review, because the guarantee is only worth anything if it
/// cannot quietly lapse.
/// </para>
/// <para>
/// Everything reaches the machine through <see cref="IBrokerClient"/>.
/// </para>
/// </remarks>
public sealed partial class MainWindowViewModel : ObservableObject
{
    private readonly IBrokerClient _broker;

    [ObservableProperty]
    private string _brokerStatus = Strings.BrokerStatusDisconnected;

    [ObservableProperty]
    private string _catalogStatus = Strings.CatalogStatusUnknown;

    /// <summary>
    /// Initialises the view model.
    /// </summary>
    /// <param name="broker">The broker connection.</param>
    public MainWindowViewModel(IBrokerClient broker) => _broker = broker;

    /// <summary>
    /// Performs the broker handshake and reflects the result.
    /// </summary>
    /// <param name="cancellationToken">Cancels the handshake.</param>
    public async Task ConnectAsync(CancellationToken cancellationToken)
    {
        var info = await _broker.HelloAsync(cancellationToken).ConfigureAwait(true);

        BrokerStatus = Strings.BrokerStatusConnected(info.BrokerVersion, info.Elevated);

        // An unverified catalog is refused outright, never used with a warning
        // (docs/04-CATALOG-SCHEMA.md), so this only distinguishes "verified"
        // from "no catalog loaded".
        CatalogStatus = info.CatalogSignatureValid
            ? Strings.CatalogStatusVerified(info.CatalogVersion)
            : Strings.CatalogStatusAbsent;
    }
}
