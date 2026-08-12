using WardSweep.UI.ViewModels;
using Wpf.Ui.Controls;

namespace WardSweep.UI.Views;

/// <summary>
/// The shell window.
/// </summary>
public partial class MainWindow : FluentWindow
{
    /// <summary>
    /// Initialises the window and binds it to its view model.
    /// </summary>
    /// <param name="viewModel">The shell view model.</param>
    public MainWindow(MainWindowViewModel viewModel)
    {
        ViewModel = viewModel;
        DataContext = viewModel;
        InitializeComponent();
    }

    /// <summary>
    /// Gets the shell view model.
    /// </summary>
    public MainWindowViewModel ViewModel { get; }
}
