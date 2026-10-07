using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using CodexProxyManager.Services;

namespace CodexProxyGuardian;

public enum GuardianProtectionState
{
    Initializing,
    Ready,
    Degraded,
    ProxyUnavailable,
    EngineUnavailable,
    ConfigInvalid,
    CodexNotInstalled,
    NeedsRepair
}

public enum GuardianCheckResult
{
    Pass,
    Fail,
    Unknown
}

public enum GuardianPreparationAction
{
    WaitForTarget,
    WaitForSocks5,
    ManualSetupRequired,
    ManualRepairRequired,
    AlreadyReady,
    DeferForRunningCodex,
    AttemptRepair
}

public sealed record GuardianPreparationInput(
    bool TargetFound,
    bool Socks5Validated,
    bool ServiceInstalled,
    bool DriverRunning,
    bool ConfigurationOwned,
    bool OfficialBinariesVerified,
    bool ServicePathVerified,
    bool ServiceRunning,
    bool ServiceStopped,
    bool CurrentRulesPass,
    bool TargetRunning);

public static class GuardianPreparationPolicy
{
    public static GuardianPreparationAction Decide(GuardianPreparationInput input)
    {
        if (!input.TargetFound) return GuardianPreparationAction.WaitForTarget;
        if (!input.Socks5Validated) return GuardianPreparationAction.WaitForSocks5;
        if (!input.ServiceInstalled) return GuardianPreparationAction.ManualSetupRequired;
        if (!input.DriverRunning || !input.ConfigurationOwned || !input.OfficialBinariesVerified || !input.ServicePathVerified)
            return GuardianPreparationAction.ManualRepairRequired;
        if (input.ServiceRunning && input.CurrentRulesPass) return GuardianPreparationAction.AlreadyReady;
        if (input.ServiceRunning && input.TargetRunning) return GuardianPreparationAction.DeferForRunningCodex;
        if (input.ServiceRunning || input.ServiceStopped) return GuardianPreparationAction.AttemptRepair;
        return GuardianPreparationAction.ManualRepairRequired;
    }
}

public sealed record GuardianHealthInput(
    string TargetDiscoveryStatus,
    bool ProxyEndpointConfigured,
    bool EngineRunning,
    bool DriverRunning,
    bool ConfigurationOwned,
    bool OfficialBinariesVerified,
    bool ServicePathVerified,
    GuardianCheckResult Socks5Check,
    GuardianCheckResult CurrentRulesCheck);

public static class GuardianHealthEvaluator
{
    public static (GuardianProtectionState State, string Detail) Evaluate(GuardianHealthInput input)
    {
        if (string.Equals(input.TargetDiscoveryStatus, "NotFound", StringComparison.OrdinalIgnoreCase))
            return (GuardianProtectionState.CodexNotInstalled, "未发现已注册的 Codex/ChatGPT Windows 应用。");
        if (!string.Equals(input.TargetDiscoveryStatus, "Found", StringComparison.OrdinalIgnoreCase))
            return (GuardianProtectionState.NeedsRepair, "暂时无法安全确认 Codex 安装信息；等待重新发现。");
        if (!input.ProxyEndpointConfigured)
            return (GuardianProtectionState.ProxyUnavailable, "没有可用的 SOCKS5 候选端点；请检查代理设置。");
        if (!input.EngineRunning || !input.DriverRunning)
            return (GuardianProtectionState.EngineUnavailable, "ProxiFyre 服务或过滤驱动未处于运行状态。");
        if (!input.ConfigurationOwned || !input.OfficialBinariesVerified || !input.ServicePathVerified)
            return (GuardianProtectionState.ConfigInvalid, "引擎配置所有权、官方文件或服务路径未全部通过核验。");
        if (input.CurrentRulesCheck == GuardianCheckResult.Fail)
            return (GuardianProtectionState.NeedsRepair, "当前引擎配置与已发现的 Codex 安装不匹配。");
        if (input.Socks5Check == GuardianCheckResult.Fail)
            return (GuardianProtectionState.ProxyUnavailable, "代理端点未通过 SOCKS5 协议验证。");
        if (input.CurrentRulesCheck != GuardianCheckResult.Pass || input.Socks5Check != GuardianCheckResult.Pass)
            return (GuardianProtectionState.Degraded, "后台组件可读，但 SOCKS5 或当前 Codex 规则尚未完成验证。");

        return (GuardianProtectionState.Ready, "SOCKS5、引擎和当前 Codex 规则均通过检查。");
    }
}

public sealed record GuardianSnapshot(
    string GuardianVersion,
    string RuntimeMode,
    int ProcessId,
    DateTimeOffset CapturedAt,
    GuardianProtectionState State,
    string Detail,
    string TargetDiscoveryStatus,
    string? PackageFamilyName,
    string? PackageFullName,
    string? PackageVersion,
    string? Publisher,
    string? PublisherDisplayName,
    string? InstallLocation,
    IReadOnlyList<string> TargetExecutablePaths,
    IReadOnlyList<TargetExecutableComponent> TargetComponents,
    string? ProxyEndpoint,
    string ProxySource,
    string ProxyEndpointType,
    string Socks5Status,
    string ServiceStatus,
    string DriverStatus,
    bool ConfigurationOwned,
    string ConfigurationStatus,
    string? ConfigurationSha256,
    bool OfficialBinariesVerified,
    bool ServicePathVerified,
    string CurrentRulesStatus);

public sealed class GuardianSnapshotCollector
{
    private readonly TargetApplicationService _targetDiscovery = new();
    private readonly ProxySettingsService _proxySettings = new();
    private int _repairAttempts;
    private DateTimeOffset _nextRepairAttemptAt;

    public async Task<GuardianSnapshot> CollectAsync(string runtimeMode, CancellationToken cancellationToken = default)
    {
        var capturedAt = DateTimeOffset.UtcNow;
        var settings = _proxySettings.Load();
        var discovery = _targetDiscovery.DiscoverInstalled(settings?.SelectedPackageFullName);
        var systemProxy = _proxySettings.ReadSystemProxy();
        var (endpoint, source) = ResolveEndpoint(settings, systemProxy);
        var target = discovery.Application;
        var endpointProbe = endpoint is null
            ? null
            : await ProxyEndpointDetector.ProbeEndpointAsync(endpoint, source, TimeSpan.FromSeconds(3), cancellationToken).ConfigureAwait(false);

        var preparationDetail = runtimeMode == "Background"
            ? await PrepareIfNeededAsync(target, discovery.Status, endpoint, endpointProbe, cancellationToken).ConfigureAwait(false)
            : "只读快照；未尝试启动或修改 ProxiFyre。";
        var engine = ProxyEngineService.GetStatus();
        var socks5Check = endpointProbe is null
            ? GuardianCheckResult.Unknown
            : endpointProbe.Socks5Usable
                ? GuardianCheckResult.Pass
                : endpointProbe.Type == ProxyEndpointType.Unknown
                    ? GuardianCheckResult.Unknown
                    : GuardianCheckResult.Fail;
        var ruleVerification = ProxyEngineService.VerifyCurrentRules(endpoint, target?.RuleExecutablePaths);
        var rulesCheck = ruleVerification.Status switch
        {
            "Pass" => GuardianCheckResult.Pass,
            "Fail" => GuardianCheckResult.Fail,
            _ => GuardianCheckResult.Unknown
        };
        var (state, detail) = GuardianHealthEvaluator.Evaluate(new GuardianHealthInput(
            discovery.Status,
            endpoint is not null,
            engine.IsRunning,
            string.Equals(engine.Driver, "运行中", StringComparison.Ordinal),
            engine.ConfigurationOwned,
            engine.OfficialBinariesVerified,
            engine.ServicePathVerified,
            socks5Check,
            rulesCheck));
        if (endpointProbe is not null && !endpointProbe.Socks5Usable)
            detail += $" 端点检测：{endpointProbe.Type}；{endpointProbe.Detail}";
        if (rulesCheck != GuardianCheckResult.Pass)
            detail += " 当前规则：" + ruleVerification.Detail;
        if (!string.IsNullOrWhiteSpace(preparationDetail))
            detail += " 登录准备：" + preparationDetail;

        return new GuardianSnapshot(
            GuardianVersion: typeof(GuardianSnapshotCollector).Assembly.GetName().Version?.ToString() ?? "Unknown",
            RuntimeMode: runtimeMode,
            ProcessId: Environment.ProcessId,
            CapturedAt: capturedAt,
            State: state,
            Detail: detail,
            TargetDiscoveryStatus: discovery.Status,
            PackageFamilyName: target?.PackageFamilyName,
            PackageFullName: target?.PackageFullName,
            PackageVersion: target?.Version,
            Publisher: target?.Publisher,
            PublisherDisplayName: target?.PublisherDisplayName,
            InstallLocation: target?.InstallLocation,
            TargetExecutablePaths: target?.RuleExecutablePaths ?? Array.Empty<string>(),
            TargetComponents: target?.KnownComponents ?? Array.Empty<TargetExecutableComponent>(),
            ProxyEndpoint: endpoint?.Display,
            ProxySource: source,
            ProxyEndpointType: endpointProbe?.Type.ToString() ?? "Unknown / NotTested",
            Socks5Status: endpointProbe is null
                ? "NotTested"
                : endpointProbe.Socks5Usable
                    ? "Pass"
                    : $"Fail · {endpointProbe.Socks5Stage} · {endpointProbe.Detail}",
            ServiceStatus: engine.Service,
            DriverStatus: engine.Driver,
            ConfigurationOwned: engine.ConfigurationOwned,
            ConfigurationStatus: engine.ConfigurationState,
            ConfigurationSha256: engine.ConfigurationSha256,
            OfficialBinariesVerified: engine.OfficialBinariesVerified,
            ServicePathVerified: engine.ServicePathVerified,
            CurrentRulesStatus: rulesCheck == GuardianCheckResult.Pass
                ? "Pass · " + ruleVerification.Detail
                : rulesCheck + " · " + ruleVerification.Detail);
    }

    private async Task<string> PrepareIfNeededAsync(
        TargetApplication? target,
        string discoveryStatus,
        ProxyEndpoint? endpoint,
        ProxyEndpointProbeResult? endpointProbe,
        CancellationToken cancellationToken)
    {
        if (!string.Equals(discoveryStatus, "Found", StringComparison.OrdinalIgnoreCase) || target is null)
            return "未发现可安全匹配的 Codex 安装；没有执行引擎操作。";
        if (endpoint is null || endpointProbe is null)
            return "没有固定代理 endpoint；没有执行引擎操作。";
        if (!endpointProbe.Socks5Usable)
            return $"SOCKS5 未通过（{endpointProbe.Type}）；没有启动或修改引擎。";

        var engine = ProxyEngineService.GetStatus();
        var ruleStatus = ProxyEngineService.VerifyCurrentRules(endpoint, target.RuleExecutablePaths);
        var targetRunning = false;
        if (engine.Service == "运行中" && ruleStatus.Status != "Pass")
        {
            var runtime = await Task.Run(() => _targetDiscovery.CaptureRuntime(target), cancellationToken).ConfigureAwait(false);
            targetRunning = runtime.Instances.Count > 0 || runtime.KnownComponentProcesses.Count > 0;
        }

        var preparationAction = GuardianPreparationPolicy.Decide(new GuardianPreparationInput(
            TargetFound: true,
            Socks5Validated: true,
            ServiceInstalled: engine.Service != "未安装",
            DriverRunning: engine.Driver == "运行中",
            ConfigurationOwned: engine.ConfigurationOwned,
            OfficialBinariesVerified: engine.OfficialBinariesVerified,
            ServicePathVerified: engine.ServicePathVerified,
            ServiceRunning: engine.Service == "运行中",
            ServiceStopped: engine.Service == "已停止",
            CurrentRulesPass: ruleStatus.Status == "Pass",
            TargetRunning: targetRunning));

        switch (preparationAction)
        {
            case GuardianPreparationAction.AlreadyReady:
                _repairAttempts = 0;
                _nextRepairAttemptAt = DateTimeOffset.MinValue;
                return "已有已验证保护，无需重启服务。";
            case GuardianPreparationAction.ManualSetupRequired:
                return "ProxiFyre 尚未安装；登录任务不会静默安装驱动，请先在管理器中手动应用保护。";
            case GuardianPreparationAction.ManualRepairRequired:
                return $"引擎状态需手动检查（服务={engine.Service}，驱动={engine.Driver}，所有权={engine.ConfigurationOwned}，官方二进制={engine.OfficialBinariesVerified}，服务路径={engine.ServicePathVerified}）；Guardian 未接管或修改服务。";
            case GuardianPreparationAction.DeferForRunningCodex:
                return "当前 Codex/ChatGPT 仍在运行，规则更新需要重启过滤服务；已推迟以保留会话。";
            case GuardianPreparationAction.WaitForTarget:
                return "未发现可安全匹配的 Codex 安装；没有执行引擎操作。";
            case GuardianPreparationAction.WaitForSocks5:
                return "SOCKS5 未通过协议验证；没有启动或修改引擎。";
        }

        if (_repairAttempts >= 3)
            return "本 Guardian 会话的自动修复上限已达 3 次；保留当前服务状态，等待人工检查。";
        if (DateTimeOffset.UtcNow < _nextRepairAttemptAt)
            return $"自动修复已退避到 {_nextRepairAttemptAt:O}；当前规则状态 {ruleStatus.Status}。";

        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var result = await Task.Run(
                () => ProxyEngineService.EnsureExistingProtectionForGuardian(endpoint, target),
                cancellationToken).ConfigureAwait(false);
            _repairAttempts = 0;
            _nextRepairAttemptAt = DateTimeOffset.MinValue;
            return result;
        }
        catch (Exception ex) when (ex is InvalidOperationException or IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or TimeoutException or InvalidDataException)
        {
            _repairAttempts++;
            var delays = new[] { TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(15) };
            _nextRepairAttemptAt = DateTimeOffset.UtcNow + delays[Math.Min(_repairAttempts - 1, delays.Length - 1)];
            return $"自动准备失败（{ex.GetType().Name}）；第 {_repairAttempts}/3 次，退避后有限重试。未启动 Codex。";
        }
    }

    private static (ProxyEndpoint? Endpoint, string Source) ResolveEndpoint(AppSettings? settings, SystemProxyInfo systemProxy)
    {
        if (settings is { FollowSystemProxy: false })
        {
            return settings.CustomHost is not null && settings.CustomPort is not null
                   && ProxyEndpoint.TryCreate(settings.CustomHost, settings.CustomPort.Value.ToString(), out var custom, out _)
                ? (custom, "SavedCustom")
                : (null, "SavedCustomInvalid");
        }

        return systemProxy.Endpoint is null
            ? (null, "WindowsProxyUnavailable")
            : (systemProxy.Endpoint, "WindowsProxy");
    }
}

public sealed class GuardianSnapshotStore
{
    private const long MaxLogBytes = 512 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = CreateJsonOptions();
    private GuardianSnapshot? _previousSnapshot;
    private readonly string _directory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "CodexProxyManagerPywBranch");

    public string StatusPath => Path.Combine(_directory, "guardian-status.json");

    public async Task WriteAsync(GuardianSnapshot snapshot, GuardianProtectionState? previousState, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(_directory);
        var json = JsonSerializer.Serialize(snapshot, JsonOptions);
        var tempPath = StatusPath + ".tmp." + Environment.ProcessId + "." + Guid.NewGuid().ToString("N");
        try
        {
            await File.WriteAllTextAsync(tempPath, json, new UTF8Encoding(false), cancellationToken);
            File.Move(tempPath, StatusPath, overwrite: true);
        }
        finally
        {
            try { File.Delete(tempPath); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }

        var identityChanged = _previousSnapshot is not null
            && (!string.Equals(_previousSnapshot.PackageFullName, snapshot.PackageFullName, StringComparison.OrdinalIgnoreCase)
                || !_previousSnapshot.TargetExecutablePaths.SequenceEqual(snapshot.TargetExecutablePaths, StringComparer.OrdinalIgnoreCase));
        var rulesChanged = _previousSnapshot is not null
            && !string.Equals(_previousSnapshot.CurrentRulesStatus, snapshot.CurrentRulesStatus, StringComparison.Ordinal);
        if (previousState != snapshot.State || identityChanged || rulesChanged)
            AppendStateChange(snapshot);
        _previousSnapshot = snapshot;
    }

    private void AppendStateChange(GuardianSnapshot snapshot)
    {
        var logPath = Path.Combine(_directory, "guardian.log");
        try
        {
            if (File.Exists(logPath) && new FileInfo(logPath).Length >= MaxLogBytes)
                File.Move(logPath, logPath + ".1", overwrite: true);
            var line = $"{snapshot.CapturedAt:O} state={snapshot.State} target={snapshot.TargetDiscoveryStatus} service={snapshot.ServiceStatus} driver={snapshot.DriverStatus} detail={snapshot.Detail}";
            if (_previousSnapshot is not null)
                line += $" previousPackage={_previousSnapshot.PackageFullName ?? "None"} currentPackage={snapshot.PackageFullName ?? "None"}"
                    + $" previousPaths={FormatPaths(_previousSnapshot.TargetExecutablePaths)} currentPaths={FormatPaths(snapshot.TargetExecutablePaths)}"
                    + $" currentRules={snapshot.CurrentRulesStatus} configHash={snapshot.ConfigurationSha256 ?? "Unknown"}";
            File.AppendAllText(logPath, line + Environment.NewLine, new UTF8Encoding(false));
        }
        catch (IOException)
        {
            // A later health cycle retries; status JSON remains the current snapshot.
        }
        catch (UnauthorizedAccessException)
        {
            // Keep the background monitor alive if the log destination becomes unavailable.
        }
    }

    private static string FormatPaths(IReadOnlyList<string> paths)
    {
        var userRoot = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return string.Join("|", paths.Select(path => string.IsNullOrWhiteSpace(userRoot)
            ? "[path unavailable]" : path.Replace(userRoot, "%USERPROFILE%", StringComparison.OrdinalIgnoreCase)));
    }

    private static JsonSerializerOptions CreateJsonOptions()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = true };
        options.Converters.Add(new JsonStringEnumConverter());
        return options;
    }
}
