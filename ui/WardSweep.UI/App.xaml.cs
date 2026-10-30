using System.Windows;
using System.Windows.Threading;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using WardSweep.UI.Resources;
using WardSweep.UI.Services;
using WardSweep.UI.ViewModels;
using WardSweep.UI.Views;

namespace WardSweep.UI;

/// <summary>
/// Application entry point and composition root.
/// </summary>
public partial class App : Application
{
    private IHost? _host;

    /// <inheritdoc />
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        _host = Host.CreateDefaultBuilder()
            .ConfigureServices(static (_, services) =>
            {
                // The real client will speak the named-pipe protocol in
                // docs/08-IPC-PROTOCOL.md, which spike S3 proved and amended.
                // Until the broker serves it, this build runs against the fake
                // and says so on screen rather than pretending to be connected.
                services.AddSingleton<IBrokerClient, FakeBrokerClient>();
                services.AddSingleton<MainWindowViewModel>();
                services.AddSingleton<MainWindow>();
            })
            .Build();

        var window = _host.Services.GetRequiredService<MainWindow>();
        window.Show();
    }

    /// <inheritdoc />
    protected override void OnExit(ExitEventArgs e)
    {
        _host?.Dispose();
        _host = null;
        base.OnExit(e);
    }

    /// <summary>
    /// Logs and reports an unhandled dispatcher exception rather than vanishing.
    /// </summary>
    /// <param name="sender">The dispatcher.</param>
    /// <param name="e">The exception.</param>
    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        // docs/18-LOGGING.md wants this surfaced with an offer to open the log
        // folder. Wiring that up needs the Serilog sink, which lands with the
        // logging work; crashing silently in the meantime would be worse.
        _ = MessageBox.Show(
            e.Exception.Message,
            Strings.AppTitle,
            MessageBoxButton.OK,
            MessageBoxImage.Error);
        e.Handled = true;
    }
}
