using System.Windows;
using NovaVpn.App.Models;

namespace NovaVpn.App.Views;

/// <summary>
/// The per-profile detail/config screen, in the spirit of OpenVPN Connect's
/// profile page: rename, view the server, set the username/password, see the
/// profile id, and delete. Results are read back by the caller, which performs
/// the actual service calls.
/// </summary>
public partial class ProfileDetailDialog : Window
{
    public enum Result { Cancelled, Save, Delete }

    public Result Outcome { get; private set; } = Result.Cancelled;

    public string ProfileName { get; private set; } = "";
    public string Username { get; private set; } = "";
    public string Password { get; private set; } = "";
    public bool SavePassword { get; private set; } = true;
    /// <summary>True when a password was actually typed (so we only save then).</summary>
    public bool PasswordEntered { get; private set; }

    public ProfileDetailDialog(ProfileSummary profile)
    {
        InitializeComponent();
        Title = profile.Name;
        NameBox.Text = profile.Name;
        ServerBox.Text = string.IsNullOrEmpty(profile.Server) ? "(unknown)" : profile.Server;
        RemotesNote.Text = profile.RemoteCount > 1
            ? $"{profile.RemoteCount} servers - tries them in order"
            : "";
        UsernameBox.Text = profile.UserName;
        IdBox.Text = profile.Id;

        if (profile.NeedsPassword)
        {
            AuthNote.Text = "This profile signs in with a username and password.";
            PasswordNote.Text = profile.HasSavedPassword
                ? "A password is saved. Leave blank to keep it, or type a new one."
                : "No password saved yet.";
        }
        else
        {
            AuthNote.Text = "This profile authenticates with a certificate; " +
                            "a username and password are not required.";
            PasswordNote.Text = "";
        }
    }

    private void OnSave(object sender, RoutedEventArgs e)
    {
        ProfileName = NameBox.Text.Trim();
        Username = UsernameBox.Text.Trim();
        Password = PasswordBox.Password;
        PasswordEntered = Password.Length > 0;
        SavePassword = SaveBox.IsChecked == true;
        if (string.IsNullOrEmpty(ProfileName))
        {
            MessageBox.Show(this, "The profile name cannot be empty.", "NovaVPN",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        Outcome = Result.Save;
        DialogResult = true;
    }

    private void OnDelete(object sender, RoutedEventArgs e)
    {
        var confirm = MessageBox.Show(this,
            $"Delete the profile \"{NameBox.Text}\"? This cannot be undone.",
            "Delete profile", MessageBoxButton.OKCancel, MessageBoxImage.Warning);
        if (confirm == MessageBoxResult.OK)
        {
            Outcome = Result.Delete;
            DialogResult = true;
        }
    }
}
