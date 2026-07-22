using System.Diagnostics;
using System.Windows.Controls;
using System.Windows.Navigation;

namespace NovaVpn.App.Views;

public partial class AboutView : UserControl
{
    public AboutView() => InitializeComponent();

    private void OnNavigate(object sender, RequestNavigateEventArgs e)
    {
        // Open the project page in the default browser.
        Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true });
        e.Handled = true;
    }
}
