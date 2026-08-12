namespace WardSweep.UI.Services;

/// <summary>
/// What the broker reports when the UI first connects.
/// </summary>
/// <param name="BrokerVersion">Version of the broker executable.</param>
/// <param name="CatalogVersion">Version of the catalog the broker loaded.</param>
/// <param name="CatalogSignatureValid">
/// Whether the catalog's Ed25519 signature verified. An unverified catalog is
/// refused by the broker rather than used with a warning, so this being
/// <see langword="false"/> means no catalog is loaded at all.
/// </param>
/// <param name="Elevated">Whether the broker process is elevated.</param>
public sealed record BrokerInfo(
    string BrokerVersion,
    string CatalogVersion,
    bool CatalogSignatureValid,
    bool Elevated);
