using System.Threading;
using System.Windows;
using CodexProxyManager.Services;

namespace CodexProxyManager;

public partial class App : System.Windows.Application
{
    private Mutex? _instanceMutex;
    private bool _ownsMutex;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        if (e.Args.Length == 2
            && string.Equals(e.Args[0], GuardianTaskInstaller.HelperArgument, StringComparison.OrdinalIgnoreCase))
        {
            var exitCode = GuardianTaskInstaller.RunAdminHelper(e.Args[1]);
            Shutdown(exitCode);
            return;
        }

        if (e.Args.Length == 2
            && string.Equals(e.Args[0], ProxyEngineService.HelperArgument, StringComparison.OrdinalIgnoreCase))
        {
            var exitCode = ProxyEngineService.RunAdminHelper(e.Args[1]);
            Shutdown(exitCode);
            return;
        }

        // Keep this mutex name so an already-running v1.3.0 instance remains the singleton.
        const string mutexName = "Local\\CodexProxyManager.PywBranch.Singleton";
        _instanceMutex = new Mutex(initiallyOwned: true, mutexName, out var createdNew);
        if (!createdNew)
        {
            _instanceMutex.Dispose();
            _instanceMutex = null;
            Shutdown();
            return;
        }

        _ownsMutex = true;
        var window = new MainWindow
        {
            StartMinimized = e.Args.Any(argument => string.Equals(argument, "--minimized", StringComparison.OrdinalIgnoreCase))
        };
        MainWindow = window;
        window.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        if (_ownsMutex)
        {
            _instanceMutex?.ReleaseMutex();
        }

        _instanceMutex?.Dispose();
        base.OnExit(e);
    }
}
