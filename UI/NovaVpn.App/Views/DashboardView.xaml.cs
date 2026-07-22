using System.Windows.Controls;
using System.Windows.Input;
using NovaVpn.App.Models;
using NovaVpn.App.ViewModels;

namespace NovaVpn.App.Views;

public partial class DashboardView : UserControl
{
    public DashboardView() => InitializeComponent();

    /// <summary>Double-clicking a profile opens its detail/config screen.</summary>
    private void OnProfileDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (DataContext is MainViewModel vm &&
            (e.OriginalSource as System.Windows.FrameworkElement)?.DataContext is ProfileSummary profile &&
            vm.EditProfileCommand.CanExecute(profile))
        {
            vm.EditProfileCommand.Execute(profile);
        }
    }
}
