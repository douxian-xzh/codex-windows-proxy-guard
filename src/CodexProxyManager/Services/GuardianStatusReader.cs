using System.Diagnostics;
using System.IO;
using System.Text.Json;

namespace CodexProxyManager.Services;

public sealed record GuardianStatusView(
    string State,
    string Detail,
    bool IsLive,
    DateTimeOffset? CapturedAt,
    string? ProxyEndpoint,
    string? Socks5Status,
    string? ServiceStatus,
    string? DriverStatus,
    string? CurrentRulesStatus,
    string? PackageVersion,
    string? ProxyEndpointType = null)
{
    public string DisplayText => $"Guardian：{State} · {Detail}";
}

public static class GuardianStatusReader
{
    private static readonly TimeSpan FreshnessWindow = TimeSpan.FromMinutes(5);
    private static readonly string StatusPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "CodexProxyManagerPywBranch",
        "guardian-status.json");

    public static GuardianStatusView Read()
        => Read(StatusPath);

    internal static GuardianStatusView Read(string statusPath)
    {
        if (!File.Exists(statusPath))
            return NotRunning("尚未收到 Guardian 状态快照；后台保护尚未确认。");

        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(statusPath));
            var root = document.RootElement;
            var runtimeMode = ReadString(root, "runtimeMode");
            var capturedAt = ReadDate(root, "capturedAt");
            var state = ReadString(root, "state") ?? "Unknown";
            var detail = ReadString(root, "detail") ?? "状态详情缺失。";
            var endpoint = ReadString(root, "proxyEndpoint");
            var socks = ReadString(root, "socks5Status");
            var service = ReadString(root, "serviceStatus");
            var driver = ReadString(root, "driverStatus");
            var rules = ReadString(root, "currentRulesStatus");
            var packageVersion = ReadString(root, "packageVersion");
            var endpointType = ReadString(root, "proxyEndpointType");

            if (!string.Equals(runtimeMode, "Background", StringComparison.Ordinal))
                return new GuardianStatusView("Initializing", "Guardian 尚未持续运行。", false, capturedAt, endpoint, socks, service, driver, rules, packageVersion, endpointType);
            if (capturedAt is null || DateTimeOffset.UtcNow - capturedAt > FreshnessWindow || capturedAt > DateTimeOffset.UtcNow.AddMinutes(1))
                return new GuardianStatusView("Degraded", "Guardian 心跳已过期或时间异常。", false, capturedAt, endpoint, socks, service, driver, rules, packageVersion, endpointType);
            if (!IsGuardianProcessAlive(root))
                return new GuardianStatusView("Degraded", "状态文件存在，但 Guardian 进程未确认运行。", false, capturedAt, endpoint, socks, service, driver, rules, packageVersion, endpointType);

            if (!Version.TryParse(ReadString(root, "guardianVersion"), out var guardianVersion)
                || guardianVersion < new Version(0, 3, 0))
                return new GuardianStatusView("NeedsRepair", "后台版本需要更新。点击“更新后台”即可完成交接，无需重启 Windows；正在转发的服务和客户端保持运行。",
                    true, capturedAt, endpoint, socks, service, driver, rules, packageVersion, endpointType);

            return new GuardianStatusView(state, detail, true, capturedAt, endpoint, socks, service, driver, rules, packageVersion, endpointType);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException or JsonException or InvalidOperationException)
        {
            return new GuardianStatusView("Degraded", "无法读取 Guardian 状态（" + ex.GetType().Name + "）。", false, null, null, null, null, null, null, null);
        }
    }

    private static GuardianStatusView NotRunning(string detail) =>
        new("Initializing", detail, false, null, null, null, null, null, null, null);

    private static string? ReadString(JsonElement root, string propertyName) =>
        root.TryGetProperty(propertyName, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static DateTimeOffset? ReadDate(JsonElement root, string propertyName) =>
        root.TryGetProperty(propertyName, out var value) && value.ValueKind == JsonValueKind.String
        && DateTimeOffset.TryParse(value.GetString(), out var parsed)
            ? parsed
            : null;

    private static bool IsGuardianProcessAlive(JsonElement root)
    {
        if (!root.TryGetProperty("processId", out var processIdValue)
            || !processIdValue.TryGetInt32(out var processId)
            || processId <= 0)
            return false;

        try
        {
            using var process = Process.GetProcessById(processId);
            return string.Equals(process.ProcessName, "CodexProxyGuardian", StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return false;
        }
    }
}
