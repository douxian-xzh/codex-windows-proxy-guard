using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Text.Json;
using Microsoft.Win32;

namespace CodexProxyManager.Services;

internal sealed record ProxyEngineSetupRequest(string Action, string Host, int Port, string InstallLocation, string ExecutablePath, string[] RuleExecutablePaths,
    LegacyConfigurationConsent? LegacyConsent = null);
internal sealed record ProxyEngineSetupResponse(bool Success, string Message);
internal sealed record ProxyEngineStatus(
    string Service,
    string Driver,
    bool ConfigurationOwned = false,
    string ConfigurationState = "未检查",
    bool OfficialBinariesVerified = false,
    bool ServicePathVerified = false,
    string? ConfigurationSha256 = null)
{
    public bool IsRunning => string.Equals(Service, "运行中", StringComparison.Ordinal);
}

/// <summary>
/// Owns the per-application ProxiFyre configuration used by the current manager.
/// The helper runs elevated only while installing/configuring the driver-backed service.
/// </summary>
internal static class ProxyEngineService
{
    internal const string HelperArgument = "--proxy-engine-admin-helper";

    private const string ServiceName = "ProxiFyreService";
    private const string DriverName = "NDISRD";
    private const string PayloadFolderName = "EnginePayload";
    private const string ManagedConfigName = "app-config.json";
    private const string OwnershipFileName = "CodexProxyManager.owner.json";
    private const string RequestDirectoryName = "engine-helper";
    private const string SetupSha256 = "C08CBB5C15ACD04D77D7C330712AE366D2A9A8E2A290586E8FE9AA73C78A1908";
    private const string EngineSha256 = "B317381D7F61AF1C5A697C0DE32C7743869843FBF52DD1805E9EBD1A5612741E";
    private const string SocksifySha256 = "9C5680A36CC818E4E11A1D05FF621DCC5F917D14FE36F3405185228DBED70598";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    private static readonly Regex DiagnosticCredentialHeader = new(
        """(?i)\b(authorization|proxy-authorization|cookie|set-cookie)\b\s*[:=].*$""",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex DiagnosticSecretAssignment = new(
        """(?i)\b(access[_-]?token|refresh[_-]?token|auth[_-]?token|id[_-]?token|account[_-]?id|device[_-]?id|session[_-]?id|token|password|secret|client[_-]?secret|api[_-]?key)\b\s*[:=]\s*("[^"]*"|'[^']*'|[^\s,;]+)""",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex DiagnosticBearer = new("""(?i)\bBearer\s+\S+""", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex DiagnosticSocksCredentials = new("""(?i)\b(socks5h?://)[^/@\s:]+:[^/@\s]+@""", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex DiagnosticUserProfilePath = new("""(?i)([a-z]:\\Users\\)[^\\/\s]+""", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex DiagnosticQuery = new("""(\S+)\?[^\s]+""", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public static async Task EnsureRunningAsync(ProxyEndpoint endpoint, TargetApplication target, ProxyScopePlan scopePlan,
        LegacyConfigurationConsent? legacyConsent = null)
    {
        await ExecuteAdminHelperAsync(new ProxyEngineSetupRequest(
            "Configure", endpoint.Host, endpoint.Port, target.InstallLocation, target.ExecutablePath, scopePlan.ExecutablePaths.ToArray(), legacyConsent));
    }

    internal static IReadOnlyList<string> ReadRecentLogsForDiagnostics()
    {
        ProxyEngineStatus status;
        try
        {
            status = GetStatus();
        }
        catch (Exception ex) when (ex is InvalidOperationException or IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return ["未读取 ProxiFyre 日志：服务状态读取失败（" + ex.GetType().Name + "）。"];
        }

        if (!status.ConfigurationOwned || !status.ServicePathVerified)
            return ["未读取 ProxiFyre 日志：服务路径或配置所有权未通过核验。"];

        try
        {
            var installDirectory = Path.GetFullPath(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ProxiFyre"));
            var logDirectory = Path.GetFullPath(Path.Combine(installDirectory, "logs"));
            var rootPrefix = installDirectory.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            if (!logDirectory.StartsWith(rootPrefix, StringComparison.OrdinalIgnoreCase)
                || !Directory.Exists(logDirectory)
                || (File.GetAttributes(logDirectory) & FileAttributes.ReparsePoint) != 0)
                return ["未读取 ProxiFyre 日志：经过核验的安装目录中没有普通 logs 目录。"];

            var logFiles = Directory.EnumerateFiles(logDirectory, "logfile_*.txt", SearchOption.TopDirectoryOnly)
                .Select(path => new FileInfo(path))
                .Where(info => info.Exists && (info.Attributes & FileAttributes.ReparsePoint) == 0)
                .OrderByDescending(info => info.LastWriteTimeUtc)
                .Take(3)
                .OrderBy(info => info.LastWriteTimeUtc)
                .ToArray();
            if (logFiles.Length == 0)
                return ["未读取 ProxiFyre 日志：没有找到最近的 logfile_*.txt。"];

            var lines = new List<string>();
            foreach (var info in logFiles)
            {
                var fullPath = Path.GetFullPath(info.FullName);
                if (!fullPath.StartsWith(Path.GetFullPath(logDirectory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar,
                    StringComparison.OrdinalIgnoreCase))
                    continue;

                using var stream = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                if (stream.Length > 128 * 1024) stream.Seek(-128 * 1024, SeekOrigin.End);
                using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
                lines.Add($"--- {info.Name} · {info.LastWriteTimeUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss} ---");
                string? line;
                while ((line = reader.ReadLine()) is not null)
                    lines.Add(RedactEngineLogLine(line));
            }

            return lines.TakeLast(120).ToArray();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or System.Security.SecurityException)
        {
            return ["读取 ProxiFyre 日志失败（" + ex.GetType().Name + "）；未导出原始异常内容。"];
        }
    }

    internal static string RedactEngineLogLine(string value)
    {
        var line = value.Length > 4096 ? value[..4096] + " [truncated]" : value;
        line = DiagnosticBearer.Replace(line, "Bearer [REDACTED]");
        line = DiagnosticCredentialHeader.Replace(line, "$1=[REDACTED]");
        line = DiagnosticSecretAssignment.Replace(line, "$1=[REDACTED]");
        line = DiagnosticSocksCredentials.Replace(line, "$1[REDACTED]@");
        line = DiagnosticUserProfilePath.Replace(line, "$1[用户名已脱敏]");
        line = DiagnosticQuery.Replace(line, "$1?[REDACTED]");
        return line;
    }

    public static string EnsureExistingProtectionForGuardian(ProxyEndpoint endpoint, TargetApplication target)
    {
        if (!IsAdministratorToken())
            throw new InvalidOperationException("Guardian 当前没有最高权限令牌；为避免在登录时弹出 UAC，没有尝试控制服务。请重新注册最高权限登录任务或在管理器中手动修复。");

        TargetApplicationService.VerifyManifestRulePaths(target.InstallLocation, target.RuleExecutablePaths);
        var scopePlan = ProxyScopePolicy.CreatePlan(target.InstallLocation, target.RuleExecutablePaths);
        var status = GetStatus();
        if (status.Service == "未安装")
            throw new InvalidOperationException("ProxiFyreService 尚未安装；Guardian 不会在登录时静默安装驱动，请在管理器中手动应用保护并完成 UAC。");
        if (status.Service is "状态未知" or "正在启动" or "正在停止")
            throw new InvalidOperationException("ProxiFyreService 状态不稳定，Guardian 本轮不重启服务。");
        if (status.Driver != "运行中")
            throw new InvalidOperationException($"NDISRD 当前状态为 {status.Driver}；Guardian 不改动驱动，等待管理员手动修复。");
        if (!status.ConfigurationOwned || !status.OfficialBinariesVerified || !status.ServicePathVerified)
            throw new InvalidOperationException("配置所有权、官方引擎哈希或服务注册路径未通过核验；Guardian 不接管或重写该服务。");

        var configPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ProxiFyre", ManagedConfigName);
        var ownerPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ProxiFyre", OwnershipFileName);
        var ruleEvidence = ManagedConfigurationStore.VerifyCurrentRules(configPath, ownerPath, endpoint, scopePlan.ExecutablePaths);
        var serviceState = GetServiceStateOrMissing(ServiceName);
        if (serviceState is not (ServiceStateResult.Running or ServiceStateResult.Stopped))
            throw new InvalidOperationException("ProxiFyreService 当前不处于 Running 或 Stopped 状态；Guardian 本轮不进行配置或重启。");
        if (serviceState == ServiceStateResult.Running && ruleEvidence.Status == "Pass")
            return "ProxiFyre 与当前 Codex 规则已验证就绪，没有重启服务。";

        if (serviceState == ServiceStateResult.Running)
        {
            var runtime = new TargetApplicationService().CaptureRuntime(target);
            if (runtime.Instances.Count > 0 || runtime.KnownComponentProcesses.Count > 0)
                throw new InvalidOperationException("发现 Codex/ChatGPT 仍在运行；规则更新需要重启过滤服务，Guardian 已推迟以保留当前会话。");
        }

        if (serviceState == ServiceStateResult.Stopped && ruleEvidence.Status == "Pass")
        {
            var snapshot = ManagedConfigurationStore.CaptureSnapshot(configPath, ownerPath);
            snapshot = ManagedConfigurationStore.ClearEngineReadyEvidence(configPath, ownerPath, snapshot);
            var started = DateTimeOffset.UtcNow;
            StartService(ServiceName);
            WaitForEngineReady(Path.GetDirectoryName(configPath)!, endpoint, scopePlan.ExecutablePaths, started, TimeSpan.FromSeconds(30));
            _ = ManagedConfigurationStore.RecordEngineReady(configPath, ownerPath, snapshot, endpoint, scopePlan.ExecutablePaths, DateTimeOffset.UtcNow);
            return "已启动原有的受管理 ProxiFyre 服务；本轮日志确认当前 Codex 规则。";
        }

        ConfigureAndStart(endpoint, target.InstallLocation, scopePlan, allowFirstInstall: false);
        return "已按更新后的 Codex 安装信息应用受管理规则；服务启动日志确认规则加载。";
    }

    public static async Task StopManagedServiceAsync(TargetApplication target)
    {
        await ExecuteAdminHelperAsync(new ProxyEngineSetupRequest(
            "StopManagedService", string.Empty, 0, target.InstallLocation, target.ExecutablePath, target.RuleExecutablePaths.ToArray()));
    }

    internal static LegacyConfigurationConsent? GetLegacyConfigurationConsent()
    {
        var directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ProxiFyre");
        var config = Path.Combine(directory, ManagedConfigName);
        var owner = Path.Combine(directory, OwnershipFileName);
        if (File.Exists(config) && !File.Exists(owner) && File.Exists(Path.Combine(directory, "codex-proxy-manager.json")))
        {
            if (GetServiceStateOrMissing(ServiceName) != ServiceStateResult.Missing)
                throw new InvalidOperationException("发现旧配置及现有过滤服务。当前版本不会接管未经所有权核验的服务；请导出诊断后按维护流程处理。");
            return LegacyConfigurationMigration.Inspect(directory);
        }
        ManagedConfigurationStore.ValidateOwnership(config, owner);
        return null;
    }

    private static void ConfigureWithLegacyConsent(ProxyEndpoint endpoint, TargetApplication target,
        ProxyScopePlan scopePlan, LegacyConfigurationConsent? consent)
    {
        if (consent is null)
        {
            ConfigureAndStart(endpoint, target.InstallLocation, scopePlan);
            return;
        }
        if (GetServiceStateOrMissing(ServiceName) != ServiceStateResult.Missing)
            throw new InvalidOperationException("确认后出现现有 ProxiFyre 服务，迁移取消；不会接管或重启该服务。");
        var directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ProxiFyre");
        var archive = LegacyConfigurationMigration.Archive(directory, consent);
        try
        {
            ConfigureAndStart(endpoint, target.InstallLocation, scopePlan);
        }
        catch (Exception failure)
        {
            string recovery;
            try
            {
                // A newly running service could depend on the current file; never restore under it.
                if (GetServiceStateOrMissing(ServiceName) is not (ServiceStateResult.Missing or ServiceStateResult.Stopped))
                    throw new InvalidOperationException("过滤服务状态不允许恢复旧文件。");
                LegacyConfigurationMigration.RestoreIfEmpty(archive);
                recovery = "旧配置和标记已恢复；备份保留。";
            }
            catch (Exception restoreFailure)
            {
                recovery = "未覆盖安装目录中的新文件或不稳定服务。" + restoreFailure.Message;
            }
            throw new InvalidOperationException(failure.Message + " " + recovery + " 旧配置备份：" + archive.BackupDirectory, failure);
        }
    }

    private static async Task ExecuteAdminHelperAsync(ProxyEngineSetupRequest request)
    {
        var requestDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "CodexProxyManager",
            RequestDirectoryName);
        Directory.CreateDirectory(requestDirectory);

        var token = Guid.NewGuid().ToString("N");
        var requestPath = Path.Combine(requestDirectory, token + ".request.json");
        var resultPath = HelperMessagePaths.ResponseFor(requestPath, ".result.json");
        File.WriteAllText(
            requestPath,
            JsonSerializer.Serialize(request, JsonOptions),
            new UTF8Encoding(false));

        Process? process = null;
        try
        {
            process = StartElevatedHelper(requestPath);
            await process.WaitForExitAsync();
            var response = TryReadResponse(resultPath);
            if (process.ExitCode != 0 || response?.Success != true)
            {
                var message = response?.Message;
                if (string.IsNullOrWhiteSpace(message))
                {
                    message = $"进程过滤服务配置失败（辅助程序退出码 {process.ExitCode}）。";
                }

                throw new InvalidOperationException(message);
            }
        }
        finally
        {
            process?.Dispose();
            TryDelete(requestPath);
            TryDelete(resultPath);
        }
    }

    public static ProxyEngineStatus GetStatus()
    {
        try
        {
            var service = GetServiceState(ServiceName);
            var driver = GetServiceState(DriverName);
            var installDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ProxiFyre");
            var enginePath = Path.Combine(installDirectory, "ProxiFyre.exe");
            var configPath = Path.Combine(installDirectory, ManagedConfigName);
            var ownerPath = Path.Combine(installDirectory, OwnershipFileName);
            var owned = false;
            var configState = "未发现管理器配置";
            string? configHash = null;
            if (File.Exists(configPath) || File.Exists(ownerPath))
            {
                try
                {
                    ManagedConfigurationStore.ValidateOwnership(configPath, ownerPath);
                    owned = File.Exists(configPath) && File.Exists(ownerPath);
                    configHash = owned ? ManagedConfigurationStore.ComputeHash(configPath) : null;
                    configState = owned ? "所有权与配置指纹匹配" : "配置文件缺失";
                }
                catch (InvalidOperationException)
                {
                    configState = "配置不属于管理器或指纹已变化";
                }
            }

            var binariesVerified = File.Exists(enginePath) && File.Exists(Path.Combine(installDirectory, "socksify.dll"))
                && string.Equals(ComputeFileHash(enginePath), EngineSha256, StringComparison.OrdinalIgnoreCase)
                && string.Equals(ComputeFileHash(Path.Combine(installDirectory, "socksify.dll")), SocksifySha256, StringComparison.OrdinalIgnoreCase);
            var servicePathVerified = false;
            if (service != "未安装")
            {
                try { VerifyRegisteredServicePath(enginePath); servicePathVerified = true; }
                catch (Exception ex) when (ex is InvalidOperationException or IOException or UnauthorizedAccessException) { }
            }

            return new ProxyEngineStatus(service, driver, owned, configState, binariesVerified, servicePathVerified, configHash);
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or IOException or UnauthorizedAccessException
            or DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        {
            return new ProxyEngineStatus("状态未知", ex.Message);
        }
    }

    public static EngineRuleVerification VerifyCurrentRules(ProxyEndpoint? endpoint, IReadOnlyList<string>? rulePaths)
    {
        var installDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ProxiFyre");
        return ManagedConfigurationStore.VerifyCurrentRules(
            Path.Combine(installDirectory, ManagedConfigName),
            Path.Combine(installDirectory, OwnershipFileName),
            endpoint,
            rulePaths);
    }

    public static int RunAdminHelper(string requestPath)
    {
        string? resultPath = null;
        try
        {
            var requestDirectory = GetRequestDirectory();
            requestPath = Path.GetFullPath(requestPath);
            if (!requestPath.StartsWith(requestDirectory + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("管理员操作请求文件不在管理器临时目录中。 ");
            }

            var requestInfo = new FileInfo(requestPath);
            if (!requestInfo.Exists || (requestInfo.Attributes & FileAttributes.ReparsePoint) != 0 || requestInfo.Length is < 1 or > 64 * 1024
                || !System.Text.RegularExpressions.Regex.IsMatch(requestInfo.Name, "^[a-f0-9]{32}\\.request\\.json$", System.Text.RegularExpressions.RegexOptions.IgnoreCase))
                throw new InvalidDataException("管理员操作请求文件无效或超出限制。");

            var candidateResultPath = HelperMessagePaths.ResponseFor(requestPath, ".result.json");
            if (File.Exists(candidateResultPath) || Directory.Exists(candidateResultPath))
                throw new InvalidDataException("进程过滤助手结果路径已存在，拒绝覆盖。");
            resultPath = candidateResultPath;
            var request = JsonSerializer.Deserialize<ProxyEngineSetupRequest>(File.ReadAllText(requestPath), JsonOptions)
                ?? throw new InvalidDataException("管理员操作请求文件内容无效。");
            if (request.RuleExecutablePaths is null || request.RuleExecutablePaths.Length is < 1 or > 16)
                throw new InvalidDataException("管理员请求的应用规则数量无效。");
            var verifiedTarget = TargetApplicationService.ReadVerifiedManifestTarget(request.InstallLocation, request.RuleExecutablePaths);
            if (!request.RuleExecutablePaths.Contains(Path.GetFullPath(request.ExecutablePath), StringComparer.OrdinalIgnoreCase))
                throw new InvalidDataException("管理员请求的主程序路径不属于清单 EXE 范围。");

            switch (request.Action)
            {
                case "Configure":
                    var scopePlan = ProxyScopePolicy.CreatePlan(request.InstallLocation, request.RuleExecutablePaths);
                    if (!ProxyEndpoint.TryCreate(request.Host, request.Port.ToString(), out var endpoint, out var error))
                        throw new InvalidDataException("代理端点无效：" + error);
                    var configureRuntime = new TargetApplicationService().CaptureRuntime(verifiedTarget);
                    if (configureRuntime.Instances.Count > 0 || configureRuntime.KnownComponentProcesses.Count > 0)
                        throw new InvalidOperationException("检测到 ChatGPT 或其已审核的包内网络组件仍在运行。为避免中断现有会话，请先正常保存工作并关闭应用，再应用代理保护。");
                    ConfigureWithLegacyConsent(endpoint!, verifiedTarget, scopePlan, request.LegacyConsent);
                    break;
                case "StopManagedService":
                    var runtime = new TargetApplicationService().CaptureRuntime(verifiedTarget);
                    if (runtime.Instances.Count > 0 || runtime.KnownComponentProcesses.Count > 0)
                        throw new InvalidOperationException("检测到 ChatGPT 或其已审核的包内网络组件仍在运行。请先正常保存工作并关闭应用，再停止过滤服务。");
                    StopManagedService();
                    break;
                default:
                    throw new InvalidDataException("管理员操作类型不受支持。");
            }

            WriteResponse(resultPath, new ProxyEngineSetupResponse(true, request.Action == "StopManagedService"
                ? "已停止管理器拥有的 ProxiFyre 服务；NDISRD 驱动、配置与备份保留。"
                : "ProxiFyre 驱动、服务、配置指纹及启动日志门槛均通过。"));
            return 0;
        }
        catch (Exception ex)
        {
            if (resultPath is not null)
            {
                try
                {
                    WriteResponse(resultPath, new ProxyEngineSetupResponse(false, ex.Message));
                }
                catch
                {
                    // The caller reports an absent result if Windows also denies this write.
                }
            }

            return 1;
        }
    }

    private static void ConfigureAndStart(ProxyEndpoint endpoint, string packageInstallLocation, ProxyScopePlan scopePlan, bool allowFirstInstall = true)
    {
        TargetApplicationService.VerifyManifestRulePaths(packageInstallLocation, scopePlan.ExecutablePaths);
        var payloadDirectory = Path.Combine(AppContext.BaseDirectory, PayloadFolderName);
        var setupPath = Path.Combine(payloadDirectory, "ProxiFyre-2.6.1-win-x64-setup.exe");
        var sourceEnginePath = Path.Combine(payloadDirectory, "ProxiFyre.exe");
        var sourceSocksifyPath = Path.Combine(payloadDirectory, "socksify.dll");
        var setupBytes = ProtectedFileTransaction.ReadVerifiedPayload(setupPath, SetupSha256, "ProxiFyre 安装器");
        var engineBytes = ProtectedFileTransaction.ReadVerifiedPayload(sourceEnginePath, EngineSha256, "官方 ProxiFyre 2.6.1 引擎");
        var socksifyBytes = ProtectedFileTransaction.ReadVerifiedPayload(sourceSocksifyPath, SocksifySha256, "官方 SOCKS5 转发组件");

        var installDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ProxiFyre");
        var enginePath = Path.Combine(installDirectory, "ProxiFyre.exe");
        var configPath = Path.Combine(installDirectory, ManagedConfigName);
        var ownershipPath = Path.Combine(installDirectory, OwnershipFileName);
        var initialServiceState = GetServiceStateOrMissing(ServiceName);
        if (initialServiceState == ServiceStateResult.Missing && !allowFirstInstall)
            throw new InvalidOperationException("Guardian 只维护已经安装的 ProxiFyre 服务，不会在登录时安装驱动。");
        ManagedConfigurationStore.ValidateOwnership(configPath, ownershipPath);
        if (initialServiceState != ServiceStateResult.Missing && !File.Exists(ownershipPath))
            throw new InvalidOperationException("检测到现有 ProxiFyre 服务不属于本管理器；为保护其他应用的规则，本次不会停止或接管它。");

        var sourceBinariesAlreadyMatch = File.Exists(enginePath)
            && File.Exists(Path.Combine(installDirectory, "socksify.dll"))
            && string.Equals(ComputeFileHash(enginePath), EngineSha256, StringComparison.OrdinalIgnoreCase)
            && string.Equals(ComputeFileHash(Path.Combine(installDirectory, "socksify.dll")), SocksifySha256, StringComparison.OrdinalIgnoreCase);
        if (initialServiceState == ServiceStateResult.Running
            && GetServiceStateOrMissing(DriverName) == ServiceStateResult.Running
            && sourceBinariesAlreadyMatch
            && VerifyRegisteredServicePath(enginePath, throwOnFailure: false)
            && ManagedConfigurationStore.VerifyCurrentRules(configPath, ownershipPath, endpoint, scopePlan.ExecutablePaths).Status == "Pass")
            return;

        var installedByThisCall = initialServiceState == ServiceStateResult.Missing;
        if (installedByThisCall)
        {
            var setupStagePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "CodexProxyManager", "Staging", Guid.NewGuid().ToString("N") + ".exe");
            ProtectedFileTransaction.AtomicWrite(setupStagePath, setupBytes);
            try { RunSetup(setupStagePath, installDirectory); }
            finally { TryDelete(setupStagePath); }
        }
        else if (!File.Exists(enginePath))
            throw new InvalidOperationException("SCM 中已有 ProxiFyre 服务，但受保护安装目录缺少其引擎文件；拒绝重装或接管。没有启动 ChatGPT。");

        if (!File.Exists(enginePath) || !Directory.Exists(installDirectory))
            throw new InvalidOperationException("ProxiFyre 安装后没有找到受保护目录中的服务文件。没有启动 ChatGPT。");

        var serviceState = GetServiceStateOrMissing(ServiceName);
        var needsServiceRegistration = serviceState == ServiceStateResult.Missing;
        if (needsServiceRegistration && !installedByThisCall)
            throw new InvalidOperationException("官方安装器没有注册 ProxiFyreService；请检查安装结果。没有启动 ChatGPT。");
        if (!needsServiceRegistration) VerifyRegisteredServicePath(enginePath);
        if (!installedByThisCall && !File.Exists(ownershipPath))
            throw new InvalidOperationException("检测到非管理器创建的 ProxiFyre 服务配置，拒绝自动接管。");

        var serviceWasRunning = serviceState == ServiceStateResult.Running;
        if (serviceWasRunning) StopService(ServiceName);

        ManagedConfigSnapshot? snapshot = null;
        var binarySnapshots = new List<ProtectedFileSnapshot>();
        try
        {
            var binaryBackupDirectory = Path.Combine(installDirectory, "CodexProxyManagerBackups", "engine-" + DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss-fff") + "-" + Guid.NewGuid().ToString("N"));
            binarySnapshots.Add(ProtectedFileTransaction.Replace(enginePath, engineBytes, binaryBackupDirectory));
            binarySnapshots.Add(ProtectedFileTransaction.Replace(Path.Combine(installDirectory, "socksify.dll"), socksifyBytes, binaryBackupDirectory));

            snapshot = ManagedConfigurationStore.Apply(
                configPath,
                ownershipPath,
                existing => ProxiFyreConfigurationBuilder.CreateOrUpdate(endpoint, scopePlan, existing));

            if (needsServiceRegistration)
            {
                RunEngineCommand(enginePath, "install");
                VerifyRegisteredServicePath(enginePath);
            }

            var driverState = GetServiceStateOrMissing(DriverName);
            if (driverState != ServiceStateResult.Running)
                throw new InvalidOperationException(
                    $"Windows 过滤驱动 {DriverName} 当前状态为 {FormatServiceState(driverState)}。请按安装器提示重启 Windows 后再试。没有启动 ChatGPT。");

            var applyStarted = DateTimeOffset.UtcNow;
            StartService(ServiceName);
            WaitForEngineReady(installDirectory, endpoint, scopePlan.ExecutablePaths, applyStarted, TimeSpan.FromSeconds(30));
            snapshot = ManagedConfigurationStore.RecordEngineReady(
                configPath,
                ownershipPath,
                snapshot ?? throw new InvalidOperationException("配置事务没有返回回滚票据。"),
                endpoint,
                scopePlan.ExecutablePaths,
                DateTimeOffset.UtcNow);
        }
        catch (Exception failure)
        {
            var rollbackErrors = new List<string>();
            try
            {
                if (GetServiceStateOrMissing(ServiceName) == ServiceStateResult.Running) StopService(ServiceName);
            }
            catch (Exception ex) { rollbackErrors.Add("停止本轮服务：" + ex.Message); }
            if (snapshot is not null)
            {
                try { ManagedConfigurationStore.Rollback(configPath, ownershipPath, snapshot); }
                catch (Exception ex) { rollbackErrors.Add("恢复配置：" + ex.Message); }
            }
            foreach (var binary in binarySnapshots.AsEnumerable().Reverse())
            {
                try { ProtectedFileTransaction.Restore(binary); }
                catch (Exception ex) { rollbackErrors.Add("恢复 " + Path.GetFileName(binary.TargetPath) + "：" + ex.Message); }
            }
            if (rollbackErrors.Count == 0 && serviceWasRunning && !installedByThisCall)
            {
                try
                {
                    if (GetServiceStateOrMissing(DriverName) == ServiceStateResult.Running)
                        StartService(ServiceName);
                    else
                        rollbackErrors.Add("原有过滤驱动未运行，无法恢复原服务状态。");
                }
                catch (Exception ex) { rollbackErrors.Add("恢复原服务：" + ex.Message); }
            }
            var restoreMessage = rollbackErrors.Count == 0
                ? installedByThisCall
                    ? "配置与本轮文件变更已恢复；首次安装留下的官方服务和驱动保留，未启动 ChatGPT。"
                    : "配置和引擎文件已恢复到本轮操作前状态。"
                : "自动恢复未完全完成：" + string.Join("；", rollbackErrors) + "。请按候选包恢复说明检查受保护备份目录。";
            throw new InvalidOperationException(failure.Message + " " + restoreMessage, failure);
        }
    }

    private static bool IsAdministratorToken()
    {
        if (!OperatingSystem.IsWindows()) return false;
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static void StopManagedService()
    {
        var installDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ProxiFyre");
        var enginePath = Path.Combine(installDirectory, "ProxiFyre.exe");
        var configPath = Path.Combine(installDirectory, ManagedConfigName);
        var ownershipPath = Path.Combine(installDirectory, OwnershipFileName);
        if (GetServiceStateOrMissing(ServiceName) == ServiceStateResult.Missing)
            throw new InvalidOperationException("ProxiFyreService 未安装。");
        ManagedConfigurationStore.ValidateOwnership(configPath, ownershipPath);
        if (!File.Exists(ownershipPath))
            throw new InvalidOperationException("ProxiFyre 配置不属于本管理器，拒绝停止服务。");
        VerifyRegisteredServicePath(enginePath);
        if (GetServiceStateOrMissing(ServiceName) != ServiceStateResult.Running)
            throw new InvalidOperationException("ProxiFyreService 当前不是运行状态。");
        StopService(ServiceName);
    }

    private static void VerifyRegisteredServicePath(string expectedEnginePath)
    {
        using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{ServiceName}");
        var registeredCommand = key?.GetValue("ImagePath") as string;
        if (string.IsNullOrWhiteSpace(registeredCommand))
            throw new InvalidOperationException("无法读取 ProxiFyreService 注册的执行路径；拒绝操作发布目录中的另一份引擎。");

        var expanded = Environment.ExpandEnvironmentVariables(registeredCommand).Trim();
        var quoteEnd = expanded.StartsWith('"') ? expanded.IndexOf('"', 1) : -1;
        var registeredExecutable = quoteEnd > 1 ? expanded[1..quoteEnd] : expanded.Split(' ', 2)[0];
        if (!string.Equals(Path.GetFullPath(registeredExecutable), Path.GetFullPath(expectedEnginePath), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("SCM 中 ProxiFyreService 的 ImagePath 与受保护安装目录不一致；拒绝改写或重启该服务。");
    }

    private static bool VerifyRegisteredServicePath(string expectedEnginePath, bool throwOnFailure)
    {
        try
        {
            VerifyRegisteredServicePath(expectedEnginePath);
            return true;
        }
        catch (Exception ex) when (ex is InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            if (throwOnFailure) throw;
            return false;
        }
    }

    private static void WaitForEngineReady(string installDirectory, ProxyEndpoint endpoint, IReadOnlyList<string> rulePaths, DateTimeOffset started, TimeSpan timeout)
    {
        var logPath = Path.Combine(installDirectory, "logs", $"logfile_{DateTime.Now:yyyy-MM-dd}.txt");
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (DateTimeOffset.UtcNow < deadline)
        {
            if (File.Exists(logPath) && File.GetLastWriteTimeUtc(logPath) >= started.UtcDateTime.AddSeconds(-2))
            {
                using var stream = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                if (stream.Length > 512 * 1024) stream.Seek(-512 * 1024, SeekOrigin.End);
                using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
                var logTail = reader.ReadToEnd();
                var allRulesAssociated = rulePaths.All(path => logTail.Contains(
                    $"Successfully associated {path} to {endpoint.Display} SOCKS5 proxy with protocols TCP, UDP and address families IPv4, IPv6!",
                    StringComparison.OrdinalIgnoreCase));
                if (allRulesAssociated && logTail.Contains("ProxiFyre Service is running...", StringComparison.Ordinal)) return;
            }
            Thread.Sleep(500);
        }

        throw new TimeoutException(
            $"服务状态为{GetServiceState(ServiceName)}，但本轮日志没有确认全部规则关联且引擎成功启动。日志：{logPath}。没有启动 ChatGPT。");
    }

    private static void RunSetup(string setupPath, string installDirectory)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = setupPath,
            WorkingDirectory = Path.GetDirectoryName(setupPath)!,
            UseShellExecute = false,
            CreateNoWindow = false,
            WindowStyle = ProcessWindowStyle.Normal
        };

        using var setup = Process.Start(startInfo)
            ?? throw new InvalidOperationException("无法启动 ProxiFyre 安装器。");
        setup.WaitForExit();
        if (setup.ExitCode == 3010 || setup.ExitCode == 1641)
        {
            throw new InvalidOperationException("ProxiFyre 已安装所需组件，但 Windows 要求重启后才能启用过滤驱动。请重启 Windows，再由管理器启动 Codex。");
        }

        if (setup.ExitCode != 0)
        {
            throw new InvalidOperationException($"ProxiFyre 安装器未成功完成（退出码 {setup.ExitCode}）。没有启动 Codex。");
        }

        if (!File.Exists(Path.Combine(installDirectory, "ProxiFyre.exe")))
        {
            throw new InvalidOperationException("ProxiFyre 安装器已退出，但没有发现安装后的服务文件。请确认安装完成后再重试。");
        }
    }

    private static void RunEngineCommand(string enginePath, string command)
    {
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = enginePath,
            WorkingDirectory = Path.GetDirectoryName(enginePath)!,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            ArgumentList = { command }
        }) ?? throw new InvalidOperationException($"无法运行 ProxiFyre {command} 命令。");

        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        process.WaitForExit();
        var detail = string.Join(Environment.NewLine, new[] { stdoutTask.GetAwaiter().GetResult(), stderrTask.GetAwaiter().GetResult() }
            .Where(value => !string.IsNullOrWhiteSpace(value)));
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException($"ProxiFyre {command} 失败（退出码 {process.ExitCode}）。{detail}");
        }
    }

    private static void StartService(string serviceName)
    {
        using var service = OpenService(serviceName, ServiceStart | ServiceQueryStatus | ServiceStop);
        if (GetServiceState(serviceName) == "运行中")
        {
            return;
        }

        if (!StartServiceNative(service, 0, IntPtr.Zero))
        {
            var error = Marshal.GetLastWin32Error();
            if (error != ErrorServiceAlreadyRunning)
            {
                throw new Win32Exception(error, $"无法启动 Windows 服务 {serviceName}");
            }
        }

        WaitForServiceState(service, ServiceState.Running, TimeSpan.FromSeconds(40), serviceName);
    }

    private static void StopService(string serviceName)
    {
        using var service = OpenService(serviceName, ServiceStop | ServiceQueryStatus);
        if (QueryServiceState(service) == ServiceState.Stopped)
        {
            return;
        }

        if (!ControlServiceNative(service, ServiceControlStop, out _))
        {
            var error = Marshal.GetLastWin32Error();
            if (error != ErrorServiceNotActive)
            {
                throw new Win32Exception(error, $"无法停止 Windows 服务 {serviceName}");
            }
        }

        WaitForServiceState(service, ServiceState.Stopped, TimeSpan.FromSeconds(40), serviceName);
    }

    private static string GetServiceState(string serviceName) => FormatServiceState(GetServiceStateOrMissing(serviceName));

    private static ServiceStateResult GetServiceStateOrMissing(string serviceName)
    {
        IntPtr manager = OpenScManager(null, null, ScManagerConnect);
        if (manager == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "无法读取 Windows 服务管理器状态");
        }

        try
        {
            IntPtr service = OpenServiceNative(manager, serviceName, ServiceQueryStatus);
            if (service == IntPtr.Zero)
            {
                var error = Marshal.GetLastWin32Error();
                if (error == ErrorServiceDoesNotExist)
                {
                    return ServiceStateResult.Missing;
                }

                throw new Win32Exception(error, $"无法读取 Windows 服务 {serviceName}");
            }

            try
            {
                return (ServiceStateResult)QueryServiceState(service);
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(manager);
        }
    }

    private static SafeServiceHandle OpenService(string serviceName, uint desiredAccess)
    {
        IntPtr manager = OpenScManager(null, null, ScManagerConnect);
        if (manager == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "无法连接 Windows 服务管理器");
        }

        try
        {
            var service = OpenServiceNative(manager, serviceName, desiredAccess);
            if (service == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"找不到 Windows 服务 {serviceName}");
            }

            return new SafeServiceHandle(service);
        }
        finally
        {
            CloseServiceHandle(manager);
        }
    }

    private static ServiceState QueryServiceState(SafeServiceHandle service)
    {
        if (!QueryServiceStatusEx(service, ScStatusProcessInfo, out var status, (uint)Marshal.SizeOf<ServiceStatusProcess>(), out _))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "无法查询过滤服务状态");
        }

        return (ServiceState)status.CurrentState;
    }

    private static ServiceState QueryServiceState(IntPtr service)
    {
        if (!QueryServiceStatusEx(service, ScStatusProcessInfo, out var status, (uint)Marshal.SizeOf<ServiceStatusProcess>(), out _))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "无法查询过滤服务状态");
        }

        return (ServiceState)status.CurrentState;
    }

    private static void WaitForServiceState(SafeServiceHandle service, ServiceState expected, TimeSpan timeout, string name)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            var state = QueryServiceState(service);
            if (state == expected)
            {
                return;
            }

            Thread.Sleep(500);
        }

        throw new TimeoutException($"等待 Windows 服务 {name} 进入 {expected} 状态超时；当前状态：{QueryServiceState(service)}。");
    }

    private static string FormatServiceState(ServiceStateResult state) => state switch
    {
        ServiceStateResult.Missing => "未安装",
        ServiceStateResult.Stopped => "已停止",
        ServiceStateResult.StartPending => "正在启动",
        ServiceStateResult.StopPending => "正在停止",
        ServiceStateResult.Running => "运行中",
        _ => "状态未知"
    };

    private static string FormatServiceState(ServiceState state) => state switch
    {
        ServiceState.Stopped => "已停止",
        ServiceState.StartPending => "正在启动",
        ServiceState.StopPending => "正在停止",
        ServiceState.Running => "运行中",
        ServiceState.ContinuePending => "正在恢复",
        ServiceState.PausePending => "正在暂停",
        ServiceState.Paused => "已暂停",
        _ => "状态未知"
    };

    private static string GetRequestDirectory() => Path.GetFullPath(Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "CodexProxyManager",
        RequestDirectoryName));

    private static Process StartElevatedHelper(string requestPath)
    {
        var processPath = Environment.ProcessPath ?? throw new InvalidOperationException("无法确定管理器可执行文件路径。");
        var arguments = new List<string>();
        if (string.Equals(Path.GetFileNameWithoutExtension(processPath), "dotnet", StringComparison.OrdinalIgnoreCase))
        {
            var assemblyName = System.Reflection.Assembly.GetEntryAssembly()?.GetName().Name;
            if (!string.IsNullOrWhiteSpace(assemblyName))
            {
                var assemblyPath = Path.Combine(AppContext.BaseDirectory, assemblyName + ".dll");
                if (File.Exists(assemblyPath))
                {
                    arguments.Add(assemblyPath);
                }
            }
        }

        arguments.Add(HelperArgument);
        arguments.Add(requestPath);
        var startInfo = new ProcessStartInfo
        {
            FileName = processPath,
            WorkingDirectory = AppContext.BaseDirectory,
            UseShellExecute = true,
            Verb = "runas",
            WindowStyle = ProcessWindowStyle.Hidden,
            Arguments = string.Join(' ', arguments.Select(QuoteCommandLineArgument))
        };

        try
        {
            return Process.Start(startInfo) ?? throw new InvalidOperationException("无法启动提权后的进程过滤配置助手。");
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            throw new InvalidOperationException("已取消 Windows 管理员权限提示，因此没有安装或启动过滤服务，也没有启动 Codex。", ex);
        }
    }

    private static string QuoteCommandLineArgument(string value)
    {
        if (value.Length > 0 && !value.Any(char.IsWhiteSpace) && !value.Contains('"'))
        {
            return value;
        }

        var builder = new StringBuilder("\"");
        var backslashes = 0;
        foreach (var character in value)
        {
            if (character == '\\')
            {
                backslashes++;
            }
            else if (character == '"')
            {
                builder.Append('\\', backslashes * 2 + 1).Append('"');
                backslashes = 0;
            }
            else
            {
                builder.Append('\\', backslashes).Append(character);
                backslashes = 0;
            }
        }

        builder.Append('\\', backslashes * 2).Append('"');
        return builder.ToString();
    }

    private static void VerifyFileHash(string path, string expectedHash, string label)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"没有找到随管理器提供的{label}文件。请将 EnginePayload 文件夹放在管理器旁边。", path);
        }

        var actualHash = ComputeFileHash(path);
        if (!string.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException($"随管理器提供的{label}校验失败，拒绝以管理员权限运行。文件：{Path.GetFileName(path)}");
        }
    }

    private static string ComputeFileHash(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static ProxyEngineSetupResponse? TryReadResponse(string path)
    {
        try
        {
            return File.Exists(path)
                ? JsonSerializer.Deserialize<ProxyEngineSetupResponse>(File.ReadAllText(path), JsonOptions)
                : null;
        }
        catch (IOException)
        {
            return null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static void WriteResponse(string path, ProxyEngineSetupResponse response) =>
        File.WriteAllText(path, JsonSerializer.Serialize(response, JsonOptions), new UTF8Encoding(false));

    private static void TryDelete(string path)
    {
        try { File.Delete(path); } catch { }
    }

    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryStatus = 0x0004;
    private const uint ServiceStart = 0x0010;
    private const uint ServiceStop = 0x0020;
    private const uint ServiceControlStop = 0x00000001;
    private const uint ScStatusProcessInfo = 0;
    private const int ErrorServiceDoesNotExist = 1060;
    private const int ErrorServiceAlreadyRunning = 1056;
    private const int ErrorServiceNotActive = 1062;

    private enum ServiceState : uint
    {
        Stopped = 1,
        StartPending = 2,
        StopPending = 3,
        Running = 4,
        ContinuePending = 5,
        PausePending = 6,
        Paused = 7
    }

    private enum ServiceStateResult : uint
    {
        Missing = 0,
        Stopped = (uint)ServiceState.Stopped,
        StartPending = (uint)ServiceState.StartPending,
        StopPending = (uint)ServiceState.StopPending,
        Running = (uint)ServiceState.Running,
        ContinuePending = (uint)ServiceState.ContinuePending,
        PausePending = (uint)ServiceState.PausePending,
        Paused = (uint)ServiceState.Paused
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
        public uint ProcessId;
        public uint ServiceFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
    }

    private sealed class SafeServiceHandle : Microsoft.Win32.SafeHandles.SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeServiceHandle(IntPtr handle) : base(ownsHandle: true) => SetHandle(handle);
        protected override bool ReleaseHandle() => CloseServiceHandle(handle);
    }

    [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenScManager(string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", EntryPoint = "OpenServiceW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenServiceNative(IntPtr serviceManager, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", EntryPoint = "CloseServiceHandle", ExactSpelling = true, SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    [DllImport("advapi32.dll", EntryPoint = "QueryServiceStatusEx", ExactSpelling = true, SetLastError = true)]
    private static extern bool QueryServiceStatusEx(IntPtr service, uint infoLevel, out ServiceStatusProcess buffer, uint bufferSize, out uint bytesNeeded);

    [DllImport("advapi32.dll", EntryPoint = "QueryServiceStatusEx", ExactSpelling = true, SetLastError = true)]
    private static extern bool QueryServiceStatusEx(SafeServiceHandle service, uint infoLevel, out ServiceStatusProcess buffer, uint bufferSize, out uint bytesNeeded);

    [DllImport("advapi32.dll", EntryPoint = "StartServiceW", ExactSpelling = true, SetLastError = true)]
    private static extern bool StartServiceNative(SafeServiceHandle service, uint argumentCount, IntPtr arguments);

    [DllImport("advapi32.dll", EntryPoint = "ControlService", ExactSpelling = true, SetLastError = true)]
    private static extern bool ControlServiceNative(SafeServiceHandle service, uint control, out ServiceStatus status);
}
