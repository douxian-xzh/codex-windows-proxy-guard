using System.Threading;
using CodexProxyManager.Services;

namespace CodexProxyGuardian;

internal static class Program
{
    private static readonly TimeSpan HealthInterval = TimeSpan.FromMinutes(2);

    private static int Main(string[] args)
    {
        if (args.Length == 2 && string.Equals(args[0], ProxyEngineService.HelperArgument, StringComparison.OrdinalIgnoreCase))
            return ProxyEngineService.RunAdminHelper(args[1]);

        if (args.Length != 1 || (args[0] != "--once" && args[0] != "--guardian"))
            return 64;

        using var singleton = new Mutex(initiallyOwned: true, "Local\\CodexProxyGuardian.Singleton", out var createdNew);
        if (!createdNew)
            return 0;

        try
        {
            using var stopRequested = new EventWaitHandle(false, EventResetMode.ManualReset, GuardianLifecycle.StopEventName(Environment.ProcessId));
            using var controlGate = GuardianLifecycle.OpenControlGate();
            var collector = new GuardianSnapshotCollector();
            var store = new GuardianSnapshotStore();
            GuardianSnapshot snapshot;
            while (!GuardianLifecycle.TryEnterControlGate(controlGate, TimeSpan.FromMilliseconds(250)))
                if (stopRequested.WaitOne(0)) return 0;
            try
            {
                if (stopRequested.WaitOne(0)) return 0;
                snapshot = collector.CollectAsync(args[0] == "--once" ? "Once" : "Background", CancellationToken.None).GetAwaiter().GetResult();
                store.WriteAsync(snapshot, previousState: null, CancellationToken.None).GetAwaiter().GetResult();
            }
            finally { controlGate.ReleaseMutex(); }
            if (args[0] == "--once")
                return 0;

            var previousState = snapshot.State;
            while (!stopRequested.WaitOne(HealthInterval))
            {
                while (!GuardianLifecycle.TryEnterControlGate(controlGate, TimeSpan.FromMilliseconds(250)))
                    if (stopRequested.WaitOne(0)) return 0;
                try
                {
                    if (stopRequested.WaitOne(0)) return 0;
                    snapshot = collector.CollectAsync("Background", CancellationToken.None).GetAwaiter().GetResult();
                    store.WriteAsync(snapshot, previousState, CancellationToken.None).GetAwaiter().GetResult();
                    previousState = snapshot.State;
                }
                catch (Exception ex)
                {
                    var failed = snapshot with
                    {
                        CapturedAt = DateTimeOffset.UtcNow,
                        State = GuardianProtectionState.NeedsRepair,
                        Detail = "Guardian 状态采集失败（" + ex.GetType().Name + "）。"
                    };
                    store.WriteAsync(failed, previousState, CancellationToken.None).GetAwaiter().GetResult();
                    previousState = failed.State;
                }
                finally { controlGate.ReleaseMutex(); }
            }

            return 0;
        }
        catch (Exception)
        {
            return 1;
        }
    }
}
