using NovaVpn.App.Services;

namespace NovaVpn.App.ViewModels;

/// <summary>
/// The application shell: owns the navigation state and the page view models.
/// The window binds its nav rail to Pages and its content area to CurrentPage.
/// </summary>
public sealed class ShellViewModel : ObservableObject
{
    private PageViewModel _currentPage;

    public ShellViewModel(NovaVpnService service)
    {
        Dashboard = new MainViewModel(service);
        SplitTunnel = new SplitTunnelViewModel(service);
        Statistics = new StatisticsViewModel(service);
        Settings = new SettingsViewModel(service);
        Logs = new LogsViewModel(service);
        About = new AboutViewModel(service);

        Pages = new PageViewModel[]
        {
            new("Dashboard", Dashboard),
            new("Split tunnel", SplitTunnel),
            new("Statistics", Statistics),
            new("Settings", Settings),
            new("Logs", Logs),
            new("About", About),
        };
        _currentPage = Pages[0];
    }

    public MainViewModel Dashboard { get; }
    public SplitTunnelViewModel SplitTunnel { get; }
    public StatisticsViewModel Statistics { get; }
    public SettingsViewModel Settings { get; }
    public LogsViewModel Logs { get; }
    public AboutViewModel About { get; }

    public PageViewModel[] Pages { get; }

    public PageViewModel CurrentPage
    {
        get => _currentPage;
        set
        {
            if (Set(ref _currentPage, value))
            {
                _ = value.Content.OnNavigatedToAsync();
            }
        }
    }

    /// <summary>Connects to the service and loads the initial page.</summary>
    public async Task InitializeAsync()
    {
        await Dashboard.InitializeAsync().ConfigureAwait(true);
    }
}

/// <summary>A navigation entry: a title and its view model.</summary>
public sealed class PageViewModel
{
    public PageViewModel(string title, PageViewModelBase content)
    {
        Title = title;
        Content = content;
    }

    public string Title { get; }
    public PageViewModelBase Content { get; }
}

/// <summary>Base for a page view model - notified when its page is shown.</summary>
public abstract class PageViewModelBase : ObservableObject
{
    public virtual Task OnNavigatedToAsync() => Task.CompletedTask;
}
