using System.Windows;

namespace NovaVpn.App.Views;

/// <summary>
/// A small modal that collects a username/password for a profile. The password
/// is read from the PasswordBox in code-behind - WPF deliberately does not let
/// PasswordBox.Password bind, so it never sits in a bound property.
/// </summary>
public partial class CredentialDialog : Window
{
    public string Username { get; private set; } = "";
    public string Password { get; private set; } = "";
    public bool SavePassword { get; private set; } = true;

    public CredentialDialog(string profileName, string? existingUsername = null)
    {
        InitializeComponent();
        Title = $"Credentials for {profileName}";
        Prompt.Text =
            $"“{profileName}” signs in with a username and password. " +
            "Enter them to connect.";
        if (!string.IsNullOrEmpty(existingUsername))
        {
            UsernameBox.Text = existingUsername;
        }
        Loaded += (_, _) =>
        {
            if (string.IsNullOrEmpty(UsernameBox.Text)) { UsernameBox.Focus(); }
            else { PasswordBox.Focus(); }
        };
    }

    private void OnOk(object sender, RoutedEventArgs e)
    {
        Username = UsernameBox.Text.Trim();
        Password = PasswordBox.Password;
        SavePassword = SaveBox.IsChecked == true;
        DialogResult = true;
    }
}
