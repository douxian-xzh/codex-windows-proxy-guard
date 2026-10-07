using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace CodexProxyManager.Services;

/// <summary>Fixed, per-user control-plane handoff. Never controls the forwarding service or its clients.</summary>
internal static class GuardianLifecycle
{
    internal static string StopEventName(int pid) => @"Local\CodexProxyGuardian.Stop." + pid;
    internal static Mutex OpenControlGate() => new(false,
        @"Local\CodexProxyGuardian.Control." + (WindowsIdentity.GetCurrent().User?.Value
            ?? throw new InvalidOperationException("无法确认后台所属用户。")));

    internal static bool TryEnterControlGate(Mutex gate, TimeSpan timeout)
    {
        try { return gate.WaitOne(timeout); }
        catch (AbandonedMutexException) { return true; } // The lock was acquired; health checks still validate transaction ownership.
    }

    internal static bool IsCurrentRunning(string expectedPath)
    {
        foreach (var process in Process.GetProcessesByName("CodexProxyGuardian"))
        {
            using (process)
            {
                try
                {
                    if (IsOurProcess(process, out var image)
                        && string.Equals(image, expectedPath, StringComparison.OrdinalIgnoreCase)) return true;
                }
                catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or IOException or UnauthorizedAccessException) { }
            }
        }
        return false;
    }

    internal static void RetirePrevious(string expectedPath)
    {
        using var gate = OpenControlGate();
        if (!TryEnterControlGate(gate, TimeSpan.FromSeconds(140)))
            throw new InvalidOperationException("后台正在完成保护事务，请稍后更新；本次没有终止它或更改转发服务。");
        try
        {
            foreach (var process in Process.GetProcessesByName("CodexProxyGuardian"))
            {
                using (process)
                {
                    if (process.HasExited) continue;
                    if (!IsOurProcess(process, out var image)) continue;
                    if (string.Equals(image, expectedPath, StringComparison.OrdinalIgnoreCase)) continue;
                    if (EventWaitHandle.TryOpenExisting(StopEventName(process.Id), out var stop))
                    {
                        using (stop) stop.Set();
                        if (!process.WaitForExit(15_000))
                            throw new InvalidOperationException("旧后台尚未完成退出，请稍后重试；没有强制结束它。");
                    }
                    else
                    {
                        // One-time compatibility for releases that predate cooperative shutdown.
                        // Do not end a legacy worker in the middle of a possible configuration transaction.
                        var version = FileVersionInfo.GetVersionInfo(image).FileVersion;
                        if (!Version.TryParse(version, out var parsed) || parsed < new Version(0, 2, 3)
                            || parsed >= new Version(0, 3, 0))
                            throw new InvalidOperationException("发现未知版本的旧后台，拒绝强制退出，请导出诊断。");
                        WaitForLegacyIdle(process);
                        if (process.HasExited) continue;
                        // The cached process handle has already been verified by image, session and token SID.
                        // Never terminate a process tree: ProxiFyre and ChatGPT/Codex are independent processes.
                        process.Kill(entireProcessTree: false);
                        if (!process.WaitForExit(10_000))
                            throw new InvalidOperationException("旧后台退出尚未确认，请稍后重试。");
                    }
                }
            }
        }
        finally { gate.ReleaseMutex(); }
    }

    private static void WaitForLegacyIdle(Process process)
    {
        var deadline = Stopwatch.StartNew();
        while (deadline.Elapsed < TimeSpan.FromSeconds(90))
        {
            if (process.HasExited) return;
            if (LegacyIdleConfirmed(process)) return;
            Thread.Sleep(500); // Bounded upgrade-only wait; no continuous fast health polling.
        }
        throw new InvalidOperationException("旧后台尚未出现可安全交接的空闲状态，请稍后再点“更新后台”；没有停止转发服务。");
    }

    private static bool LegacyIdleConfirmed(Process process)
    {
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "CodexProxyManagerPywBranch", "guardian-status.json");
        try
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) return false;
            using var document = JsonDocument.Parse(File.ReadAllText(path));
            var root = document.RootElement;
            if (root.GetProperty("processId").GetInt32() != process.Id
                || root.GetProperty("runtimeMode").GetString() != "Background"
                || !DateTimeOffset.TryParse(root.GetProperty("capturedAt").GetString(), out var captured)) return false;
            var age = DateTimeOffset.UtcNow - captured;
            // Legacy loops tick every 120 seconds. A completed snapshot <70 seconds old leaves
            // ample time to retire this exact worker before its next possible preparation cycle.
            if (age < TimeSpan.Zero || age > TimeSpan.FromSeconds(70)
                || captured.UtcDateTime < process.StartTime.ToUniversalTime()) return false;
            var completion = File.GetLastWriteTimeUtc(path) - captured.UtcDateTime;
            if (completion < TimeSpan.Zero || completion > TimeSpan.FromSeconds(20)
                || (root.GetProperty("detail").GetString() ?? string.Empty).StartsWith("Guardian 状态采集失败", StringComparison.Ordinal)) return false;
            var engine = ProxyEngineService.GetStatus();
            return engine.IsRunning && engine.ConfigurationOwned && engine.ServicePathVerified
                && engine.OfficialBinariesVerified
                && string.Equals(root.GetProperty("configurationSha256").GetString(), engine.ConfigurationSha256,
                    StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException
            or InvalidOperationException or KeyNotFoundException or Win32Exception) { return false; }
    }

    private static bool IsOurProcess(Process process, out string image)
    {
        image = string.Empty;
        if (process.SessionId != Process.GetCurrentProcess().SessionId) return false;
        var buffer = new StringBuilder(32768);
        var length = buffer.Capacity;
        if (!QueryFullProcessImageName(process.Handle, 0, buffer, ref length))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "无法核验旧后台镜像路径。");
        image = Path.GetFullPath(buffer.ToString());
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "CodexProxyManager", "Guardian");
        var directory = Path.GetDirectoryName(image)!;
        if (!string.Equals(Path.GetDirectoryName(directory), root, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(Path.GetFileName(image), "CodexProxyGuardian.exe", StringComparison.OrdinalIgnoreCase)) return false;
        for (var cursor = directory; cursor is not null; cursor = Path.GetDirectoryName(cursor))
        {
            if ((File.GetAttributes(cursor) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("后台安装目录包含重解析点，拒绝升级操作。");
        }
        if ((File.GetAttributes(image) & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
            throw new InvalidDataException("后台镜像不是已核验的普通文件。");
        GuardianTaskInstaller.VerifyInstalledBundle(directory);
        if (!OpenProcessToken(process.Handle, 8, out var token))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            GetTokenInformation(token, 1, IntPtr.Zero, 0, out var required);
            if (required <= 0) throw new Win32Exception(Marshal.GetLastWin32Error());
            var info = Marshal.AllocHGlobal(required);
            try
            {
                if (!GetTokenInformation(token, 1, info, required, out _))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                var sid = new SecurityIdentifier(Marshal.ReadIntPtr(info)).Value;
                return string.Equals(sid, WindowsIdentity.GetCurrent().User?.Value, StringComparison.Ordinal);
            }
            finally { Marshal.FreeHGlobal(info); }
        }
        finally { CloseHandle(token); }
    }

    [DllImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder name, ref int size);
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr token, int informationClass, IntPtr information, int length, out int required);
    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern bool CloseHandle(IntPtr handle);
}
