using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Threading;
using CodexProxyManager.Services;
using WpfMessageBox = System.Windows.MessageBox;
using WpfSaveFileDialog = Microsoft.Win32.SaveFileDialog;
using WpfOpenFileDialog = Microsoft.Win32.OpenFileDialog;

namespace CodexProxyManager;

public partial class MainWindow : Window
{
    private readonly ProxySettingsService _proxySettings = new();
    private readonly SettingsStore _settingsStore;
    private readonly TargetApplicationService _targetService = new();
    private readonly WindowsConnectionObserver _connectionObserver = new();
    private readonly ObservableCollection<ConnectionDisplayRow> _connections = [];
    private readonly ObservableCollection<string> _events = [];
    private readonly DispatcherTimer _refreshTimer = new() { Interval = TimeSpan.FromSeconds(2) };
    private readonly NativeTrayIconService _trayIcon;
    private HwndSource? _windowSource;
    private CancellationTokenSource? _probeCancellation;

    private AppSettings? _settings;
    private SystemProxyInfo? _systemProxy;
    private TargetApplication? _targetApplication;
    private TargetDiscoveryResult _targetDiscovery = new(null, "Unknown", "尚未完成安装发现。");
    private TargetRuntimeSnapshot? _runtime;
    private ProxyEngineStatus _proxyEngineStatus = new("未安装", "未知");
    private ConnectionObservation? _lastObservation;
    private ProxyEndpoint? _currentEndpoint;
    private TargetLaunchResult? _lastLaunchResult;
    private CodexLogEvidence? _lastCodexLogEvidence;
    private DateTimeOffset? _engineReadyEvidenceAt;
    private Socks5ProbeResult? _lastSocksProbeResult;
    private ProxyEndpoint? _lastSocksProbeEndpoint;
    private DateTimeOffset? _lastSocksProbeAt;
    private bool _initialized;
    private bool _loadingFields;
    private bool _updatingTargetChoices;
    private bool _refreshing;
    private bool _starting;
    private bool _applyingProtection;
    private bool _stopping;
    private bool _exitRequested;
    private bool _proxyInputDirty;
    private bool _changingStartup;
    private string? _lastRouteSummary;
    private const int WmDpiChanged = 0x02E0;
    private const double PreferredWindowWidth = 1000;
    private const double PreferredWindowHeight = 820;

    public bool StartMinimized { get; init; }

    public MainWindow()
    {
        InitializeComponent();
        Title = "Codex 代理管理器 · v1.6 by 豆馅";
        ApplyAppearance();
        RestoreSections();
        FitWindowToWorkArea();
        SourceInitialized += Window_SourceInitialized;
        _settingsStore = new SettingsStore(_proxySettings);
        ConnectionGrid.ItemsSource = _connections;
        LogList.ItemsSource = _events;

        _systemProxy = _proxySettings.ReadSystemProxy();
        _settings = _settingsStore.LoadOrInitialize();
        InitializeProxyFields();
        try
        {
            StartupManager.RemoveLegacyManagerRunEntry();
        }
        catch (Exception ex)
        {
            AddEvent("移除旧版管理器登录自启项失败：" + ex.GetType().Name);
        }

        var guardianAutoStart = StartupManager.IsEnabled();
        StartupCheckBox.IsChecked = guardianAutoStart;
        if (_settings.RunAtLogon != guardianAutoStart)
        {
            _settings = _settings with { RunAtLogon = guardianAutoStart };
            _settingsStore.Save(_settings);
        }

        using var trayStream = System.Windows.Application.GetResourceStream(new Uri("pack://application:,,,/Assets/Tray.ico"))!.Stream;
        using var trayIconData = new MemoryStream();
        trayStream.CopyTo(trayIconData);
        _trayIcon = new NativeTrayIconService(
            trayIconData.ToArray(),
            Title,
            () => new System.Windows.Interop.WindowInteropHelper(this).Handle,
            ShowWindow,
            () => _ = StartTargetAsync(),
            () => _ = StopTargetAsync(),
            ExitManager);

        _refreshTimer.Tick += async (_, _) => await RefreshStateAsync();
        Loaded += MainWindow_Loaded;
        _initialized = true;
        AddEvent("管理器已启动；流量状态需要由运行后的连接观察确认。");
    }

    private void FitWindowToWorkArea()
    {
        var workArea = SystemParameters.WorkArea;
        if (workArea.Width <= 0 || workArea.Height <= 0) return;

        // Width and Height are WPF device-independent units. Keep a small margin
        // around the usable desktop so the title bar stays reachable at 150% DPI.
        var fittedWidth = Math.Min(PreferredWindowWidth, Math.Max(MinWidth, workArea.Width - 32));
        var fittedHeight = Math.Min(PreferredWindowHeight, Math.Max(MinHeight, workArea.Height - 40));
        Width = fittedWidth;
        Height = fittedHeight;
        Left = workArea.Left + (workArea.Width - fittedWidth) / 2;
        Top = workArea.Top + (workArea.Height - fittedHeight) / 2;
        WindowStartupLocation = WindowStartupLocation.Manual;
    }

    private void Window_SourceInitialized(object? sender, EventArgs e)
    {
        FitWindowToWorkArea();
        ApplyTitleBarTheme();
        _windowSource = HwndSource.FromHwnd(new WindowInteropHelper(this).Handle);
        _windowSource?.AddHook(WindowMessageHook);
    }

    private IntPtr WindowMessageHook(IntPtr hwnd, int message, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (message == WmDpiChanged)
            Dispatcher.BeginInvoke(FitWindowToWorkArea, DispatcherPriority.Loaded);
        return IntPtr.Zero;
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        if (StartMinimized)
        {
            Hide();
        }

        await RefreshStateAsync(rediscover: true);
        _refreshTimer.Start();
    }

    private void InitializeProxyFields()
    {
        _loadingFields = true;
        ProxyHostBox.Text = _settings?.CustomHost ?? string.Empty;
        ProxyPortBox.Text = _settings?.CustomPort?.ToString() ?? string.Empty;
        _loadingFields = false;
        _proxyInputDirty = false;
        TryReadCurrentEndpoint(out _);
        UpdateProxySummary();
        UpdateActionButtons();
    }

    private void ProxyInput_Changed(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        if (!_initialized || _loadingFields)
        {
            return;
        }

        _proxyInputDirty = true;
        _engineReadyEvidenceAt = null;
        var valid = TryReadCurrentEndpoint(out var error);
        ProxyEditHintText.Text = valid
            ? "有未保存的修改。点击“保存设置”后，Guardian 会低频验证该 SOCKS5 端点；不会修改 Windows 系统代理。"
            : error;
        ProxyEditHintText.SetResourceReference(System.Windows.Controls.TextBlock.ForegroundProperty, valid ? "MutedBrush" : "DangerBrush");
        UpdateProxySummary();
        UpdateActionButtons();
    }

    private void SaveProxy_Click(object sender, RoutedEventArgs e)
    {
        if (SaveCurrentProxy(followSystem: false))
        {
            AddEvent($"SOCKS5 代理端点已保存：{_currentEndpoint!.Display}；保存本身不会应用规则或修改系统代理。");
        }
    }

    private async void ApplyProxyProtection_Click(object sender, RoutedEventArgs e)
    {
        if (_applyingProtection || _probeCancellation is not null) return;
        _applyingProtection = true;
        ProbeResultText.Text = "正在检查保护准备条件…";
        ProxySection.IsExpanded = true;
        UpdateActionButtons();
        try
        {
            await RefreshStateAsync(rediscover: true);
            var target = _targetApplication;
            if (target is null)
            {
                WpfMessageBox.Show(this, "没有发现可安全确认的 ChatGPT/Codex 安装；代理保护没有应用。", "无法应用保护", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var targetRuntime = await Task.Run(() => _targetService.CaptureRuntime(target));
            if (targetRuntime.Instances.Count > 0 || targetRuntime.KnownComponentProcesses.Count > 0)
            {
                ProbeResultText.Text = "请先保存工作并正常关闭 Codex，再准备保护；尚未请求管理员权限或修改服务。";
                WpfMessageBox.Show(this, "检测到 ChatGPT/Codex 仍在运行。应用规则需要重启过滤服务；请先保存工作并正常关闭应用，再重试。", "保护现有会话", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            var legacyConsent = ProxyEngineService.GetLegacyConfigurationConsent();
            if (legacyConsent is not null)
            {
                var answer = WpfMessageBox.Show(this,
                    "发现旧版管理器留下的配置，它没有新版所有权标记，且使用旧宽范围规则。\n\n" +
                    "继续后将先备份旧配置与标记，再重新生成当前 Codex 包内的精确 EXE 规则。" +
                    "旧文件保存在 ProxiFyre\\CodexProxyManagerBackups\\legacy-*；未知配置或现有服务不会被接管。\n\n是否备份并迁移？",
                    "迁移旧版代理配置", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (answer != MessageBoxResult.Yes)
                {
                    ProbeResultText.Text = "已取消旧配置迁移；没有修改配置或请求管理员权限。";
                    return;
                }
            }
            var followSystemProxy = _settings?.FollowSystemProxy == true && !_proxyInputDirty;
            if (!SaveCurrentProxy(followSystem: followSystemProxy) || _currentEndpoint is null) return;
            var endpoint = _currentEndpoint;

            _probeCancellation = new CancellationTokenSource();
            ProbeResultText.Text = $"正在确认匿名 SOCKS5 CONNECT + TLS：{endpoint.Display}…";
            var probe = await Socks5ProxyProbe.ProbeAsync(
                endpoint, "api.openai.com", 443, validateTls: true, tlsServerName: "api.openai.com",
                TimeSpan.FromSeconds(12), _probeCancellation.Token);
            _lastSocksProbeResult = probe;
            _lastSocksProbeEndpoint = endpoint;
            _lastSocksProbeAt = DateTimeOffset.UtcNow;
            if (!probe.Success)
            {
                ProbeResultText.Text = $"SOCKS5/TLS 未通过：{probe.Stage} · {probe.Summary}；没有请求安装或启动引擎。";
                AddEvent("拒绝应用代理保护：SOCKS5/TLS 验证失败，" + probe.Stage + "。");
                return;
            }

            _probeCancellation.Dispose();
            _probeCancellation = null;
            UpdateActionButtons();

            var scopePlan = ProxyScopePolicy.CreatePlan(target.InstallLocation, target.RuleExecutablePaths);
            ProbeResultText.Text = "端点通过 SOCKS5/TLS；等待 Windows 管理员权限完成 ProxiFyre 配置…";
            AddEvent($"端点 {endpoint.Display} 的 SOCKS5 CONNECT 和 TLS 验证通过；请求应用精确 Codex 路径规则。");
            // Recheck after the network probe; the user may have opened Codex while it was pending.
            var latestRuntime = await Task.Run(() => _targetService.CaptureRuntime(target));
            if (latestRuntime.Instances.Count > 0 || latestRuntime.KnownComponentProcesses.Count > 0)
                throw new InvalidOperationException("检测期间 Codex 已启动；请正常关闭后重试。本轮没有请求管理员权限。");
            await ProxyEngineService.EnsureRunningAsync(endpoint, target, scopePlan, legacyConsent);
            _engineReadyEvidenceAt = DateTimeOffset.UtcNow;
            ProbeResultText.Text = "ProxiFyre 已启动，当前 Codex 路径规则已由本轮引擎日志确认。Responses WSS / Remote Control 仍未测试。";
            AddEvent("ProxiFyre 本轮服务 Running，日志确认当前精确 Codex 规则已加载；这不代表 Responses WSS 或 Remote Control 已通过。");
            await RefreshStateAsync(rediscover: true);
        }
        catch (OperationCanceledException)
        {
            ProbeResultText.Text = "代理保护应用已取消；没有启动 Codex。";
            AddEvent("应用代理保护已取消。");
        }
        catch (Exception ex)
        {
            ProbeResultText.Text = "代理保护应用失败：" + ProxyEngineService.RedactEngineLogLine(ex.Message);
            ShowError("应用代理保护失败", ex);
        }
        finally
        {
            _probeCancellation?.Dispose();
            _probeCancellation = null;
            _applyingProtection = false;
            UpdateActionButtons();
        }
    }

    private void ReloadSystemProxy_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            _systemProxy = _proxySettings.ReadSystemProxy();
            _loadingFields = true;
            ProxyHostBox.Text = _systemProxy.Endpoint?.Host ?? string.Empty;
            ProxyPortBox.Text = _systemProxy.Endpoint?.Port.ToString() ?? string.Empty;
            _loadingFields = false;
            _proxyInputDirty = false;

            _settings = new AppSettings(
                FollowSystemProxy: true,
                CustomHost: _systemProxy.Endpoint?.Host,
                CustomPort: _systemProxy.Endpoint?.Port,
                RunAtLogon: StartupCheckBox.IsChecked == true,
                SelectedPackageFullName: _settings?.SelectedPackageFullName);
            _settingsStore.Save(_settings);
            TryReadCurrentEndpoint(out _);
            ProxyEditHintText.Text = _systemProxy.Endpoint is null
                ? "未找到可识别的固定系统代理。PAC/WPAD 不能直接作为固定代理端点启动。"
                : "已重新读取并保存 Windows 当前用户的固定代理地址。";
            ProxyEditHintText.SetResourceReference(System.Windows.Controls.TextBlock.ForegroundProperty, "MutedBrush");
            UpdateProxySummary();
            UpdateActionButtons();
            AddEvent(_systemProxy.Endpoint is null
                ? "已读取系统代理设置，但没有可识别的固定代理端点。"
                : $"已从系统代理读取 {_systemProxy.Endpoint.Display}。");
        }
        catch (Exception ex)
        {
            _loadingFields = false;
            ShowError("读取或保存系统代理失败", ex);
        }
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await RefreshStateAsync(rediscover: true);

    private async void ProbeProxy_Click(object sender, RoutedEventArgs e)
    {
        if (_probeCancellation is not null) return;
        TryReadCurrentEndpoint(out _);
        var currentInput = _currentEndpoint;
        var candidates = ProxyEndpointDetector.BuildCandidates(currentInput, _settings, _systemProxy, _proxyInputDirty);
        if (candidates.Count == 0)
        {
            ProbeResultText.Text = "没有可检测端点；请输入 SOCKS5 代理 IP/主机名和端口。";
            return;
        }

        _probeCancellation = new CancellationTokenSource();
        UpdateActionButtons();
        ProbeResultText.Text = $"正在验证 {candidates.Count} 个有限候选：SOCKS5 CONNECT / HTTP CONNECT；不会改系统代理…";
        try
        {
            var detections = await ProxyEndpointDetector.DetectCandidatesAsync(
                currentInput,
                _settings,
                _systemProxy,
                _proxyInputDirty,
                TimeSpan.FromSeconds(2),
                _probeCancellation.Token);
            var candidateSummary = string.Join("；", detections.Select(result => $"{result.Endpoint.Display}={result.Type}"));
            var usableCandidate = detections.FirstOrDefault(result => result.Socks5Usable);
            AddEvent("代理候选协议检测：" + candidateSummary);

            if (usableCandidate is null)
            {
                var reason = detections.Any(result => result.Type == ProxyEndpointType.HttpProxy)
                    ? "检测到 HTTP 代理候选；ProxiFyre 需要真正支持 SOCKS5 的端点。请在代理软件中选 SOCKS5/mixed 端口或手动填写。"
                    : detections.Any(result => result.Socks5ProtocolIdentified)
                        ? "发现 SOCKS5 协议，但匿名 CONNECT 未通过；当前版本不支持代理认证。请填入可匿名使用的 SOCKS5/mixed 端口。"
                        : "未发现可用 SOCKS5；请填写实际 SOCKS5/mixed 代理地址。不会自动切换代理软件的全局模式。";
                ProbeResultText.Text = reason + " 候选结果：" + candidateSummary;
                return;
            }

            var endpoint = usableCandidate.Endpoint;
            var inputChanged = currentInput is null || !string.Equals(currentInput.Display, endpoint.Display, StringComparison.OrdinalIgnoreCase);
            if (inputChanged)
            {
                _loadingFields = true;
                ProxyHostBox.Text = endpoint.Host;
                ProxyPortBox.Text = endpoint.Port.ToString();
                _loadingFields = false;
                _proxyInputDirty = true;
                TryReadCurrentEndpoint(out _);
                ProxyEditHintText.Text = $"已找到并填入 SOCKS5 候选 {endpoint.Display}（{usableCandidate.Source}）；点击“保存设置”后持久化。系统代理未修改。";
                ProxyEditHintText.SetResourceReference(System.Windows.Controls.TextBlock.ForegroundProperty, "MutedBrush");
                UpdateProxySummary();
            }

            ProbeResultText.Text = $"已识别 {usableCandidate.Type}：{endpoint.Display}（{usableCandidate.Source}）；正在验证 TLS…";
            var result = await Socks5ProxyProbe.ProbeAsync(
                endpoint, "api.openai.com", 443, validateTls: true, tlsServerName: "api.openai.com",
                TimeSpan.FromSeconds(12), _probeCancellation.Token);
            _lastSocksProbeResult = result;
            _lastSocksProbeEndpoint = endpoint;
            _lastSocksProbeAt = DateTimeOffset.UtcNow;
            ProbeResultText.Text = $"候选 {usableCandidate.Type} · SOCKS5/TLS {result.Stage} · {result.Summary}" +
                (inputChanged ? " 已填入代理输入框但尚未保存；系统代理未修改。" : string.Empty);
            AddEvent($"候选 {usableCandidate.Type} 来源={usableCandidate.Source}；SOCKS5/TLS {result.Stage}：{result.Summary}");
        }
        catch (OperationCanceledException)
        {
            ProbeResultText.Text = "代理候选检测已取消。";
            AddEvent("代理候选检测已取消。");
        }
        catch (Exception ex)
        {
            ProbeResultText.Text = "探测异常：" + ex.GetType().Name;
            AddEvent("SOCKS5/TLS 探测异常：" + ex.GetType().Name);
        }
        finally
        {
            _probeCancellation.Dispose();
            _probeCancellation = null;
            UpdateActionButtons();
        }
    }

    private void CancelProbe_Click(object sender, RoutedEventArgs e) => _probeCancellation?.Cancel();

    private void ClearLog_Click(object sender, RoutedEventArgs e) => _events.Clear();

    private void ReadCodexLog_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new WpfOpenFileDialog
        {
            Title = "选择 ChatGPT / Codex 诊断日志（不会读取会话或认证文件）",
            Filter = "文本诊断日志 (*.log;*.txt)|*.log;*.txt",
            CheckFileExists = true,
            Multiselect = false
        };
        if (dialog.ShowDialog(this) != true) return;

        try
        {
            _lastCodexLogEvidence = CodexLogEvidenceReader.Read(dialog.FileName);
            CodexEvidenceText.Text =
                $"日志 { _lastCodexLogEvidence.SourceFileName } · 修改时间 {_lastCodexLogEvidence.FileModifiedAt.ToLocalTime():yyyy-MM-dd HH:mm:ss}{Environment.NewLine}" +
                $"Responses：{_lastCodexLogEvidence.ResponsesStatus} · Remote：{_lastCodexLogEvidence.RemoteStatus} · 相关事件 {_lastCodexLogEvidence.RelevantEventCount}" +
                (_lastCodexLogEvidence.TailTruncated ? " · 仅分析最后 2 MiB" : "") +
                $"{Environment.NewLine}{_lastCodexLogEvidence.PrivacyNote}";
            AddEvent($"客户端日志摘要完成：Responses={_lastCodexLogEvidence.ResponsesStatus}，Remote={_lastCodexLogEvidence.RemoteStatus}；未保留原始日志行。");
            UpdateGuardianStatus();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            CodexEvidenceText.Text = "日志读取失败；没有保留日志内容。";
            AddEvent("客户端诊断日志读取失败：" + ex.GetType().Name);
            WpfMessageBox.Show(this, "无法读取该诊断日志。请仅选择 ChatGPT/Codex 的 .log 或 .txt 日志；不支持会话、配置、认证和数据库文件。", "日志读取失败", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private async void ExportDiagnostics_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new WpfSaveFileDialog
        {
            Title = "导出 Codex 代理管理器诊断信息",
            FileName = $"CodexProxyManager-诊断-{DateTime.Now:yyyyMMdd-HHmmss}.txt",
            DefaultExt = ".txt",
            Filter = "文本文件 (*.txt)|*.txt"
        };
        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        try
        {
            var networkDiagnostics = await NetworkDiagnosticsCollector.CaptureAsync();
            var recentEngineLogs = await Task.Run(ProxyEngineService.ReadRecentLogsForDiagnostics);
            File.WriteAllText(dialog.FileName, BuildDiagnosticsReport(networkDiagnostics, recentEngineLogs), new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            AddEvent("诊断信息已导出到 " + dialog.FileName);
            WpfMessageBox.Show(this, "诊断信息已导出：\n" + dialog.FileName, "导出完成", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            ShowError("导出诊断信息失败", ex);
        }
    }

    private async void StartButton_Click(object sender, RoutedEventArgs e) => await StartTargetAsync();

    private async void StopButton_Click(object sender, RoutedEventArgs e) => await StopTargetAsync();

    private async void TargetChoice_Changed(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (_updatingTargetChoices || !_initialized || TargetChoiceCombo.SelectedItem is not TargetChoiceItem choice)
            return;

        try
        {
            _settings = (_settings ?? new AppSettings(false, null, null, false)) with
            {
                SelectedPackageFullName = choice.Application.PackageFullName
            };
            _settingsStore.Save(_settings);
            _targetApplication = choice.Application;
            _targetDiscovery = new TargetDiscoveryResult(_targetApplication, "Found", Candidates: _targetDiscovery.Candidates);
            TargetInfoText.Text = DescribeTargetIdentity(_targetApplication) + " · 已记住所选安装";
            ScopeSummaryText.Text = DescribeTargetScope(_targetApplication);
            AddEvent($"已选择 ChatGPT 安装 {_targetApplication.Version}；规则只包含已审核客户端及后台缓存的具体路径。");
            await RefreshStateAsync();
        }
        catch (Exception ex)
        {
            ShowError("保存 ChatGPT 安装选择失败", ex);
        }
    }

    private async void StopProxyService_Click(object sender, RoutedEventArgs e)
    {
        if (_targetApplication is null)
        {
            WpfMessageBox.Show(this, "无法确认 ChatGPT 安装范围，停止服务操作已禁用。", "无法停止代理服务", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        await RefreshStateAsync();
        if ((_runtime?.Instances.Count ?? 0) > 0)
        {
            WpfMessageBox.Show(this, "检测到 ChatGPT 仍在运行。请先保存工作并关闭应用，再停止代理服务。", "代理服务保持运行", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var answer = WpfMessageBox.Show(
            this,
            "停止后，ChatGPT 新连接将不再由 ProxiFyre 转发，可能恢复原始网络路径。此操作只停止本管理器拥有且路径核验通过的 ProxiFyre 服务；不会停止 NDISRD 驱动、删除配置或改变系统代理。确定继续？",
            "停止 Codex 代理服务",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (answer != MessageBoxResult.Yes) return;

        _stopping = true;
        UpdateActionButtons();
        try
        {
            await ProxyEngineService.StopManagedServiceAsync(_targetApplication);
            _engineReadyEvidenceAt = null;
            AddEvent("已停止管理器拥有的 ProxiFyre 服务；过滤驱动、规则配置和备份保留。关闭管理器不会自动停止服务。");
            await RefreshStateAsync();
        }
        catch (Exception ex)
        {
            ShowError("停止代理服务失败", ex);
        }
        finally
        {
            _stopping = false;
            UpdateActionButtons();
        }
    }

    private async void StartupCheckBox_Changed(object sender, RoutedEventArgs e)
    {
        if (!_initialized || _settings is null || _changingStartup)
        {
            return;
        }

        await ChangeGuardianAsync(StartupCheckBox.IsChecked == true);
    }

    private async void UpdateGuardian_Click(object sender, RoutedEventArgs e)
    {
        if (_changingStartup || !_initialized || _settings is null) return;
        await ChangeGuardianAsync(true);
    }

    private async Task ChangeGuardianAsync(bool enabled)
    {
        _changingStartup = true;
        UpdateActionButtons();
        ProbeResultText.Text = enabled ? "正在更新并交接后台，请完成管理员授权；无需重启 Windows。" : "正在更新登录设置…";
        OperationProgressText.Visibility = Visibility.Visible;
        try
        {
            var warning = await Task.Run(() => StartupManager.SetEnabled(enabled));
            _settings = _settings! with { RunAtLogon = enabled };
            _settingsStore.Save(_settings);
            StartupCheckBox.IsChecked = enabled;
            ProbeResultText.Text = enabled ? "新版后台已接替；转发服务和当前会话保持运行。保护就绪见实时状态。" : "已取消登录后自动准备；现有代理服务和后台仍运行。";
            AddEvent(enabled
                ? "新版 Guardian 已确认运行，无需重启 Windows；实时保护状态等待快照确认。"
                : "已移除 Guardian 登录任务；此操作没有停止或启动 ProxiFyre 服务。");
            if (warning is not null)
            {
                AddEvent(warning);
                WpfMessageBox.Show(this, warning, "后台任务已注册，启动待确认", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
        catch (Exception ex)
        {
            // Read actual registration after cancellation/partial success; suppress recursive UAC.
            var registered = StartupManager.IsEnabled();
            StartupCheckBox.IsChecked = registered;
            _settings = _settings! with { RunAtLogon = registered };
            ProbeResultText.Text = "后台更新未完成：" + ProxyEngineService.RedactEngineLogLine(ex.Message);
            ShowError("修改开机自启设置失败", ex);
        }
        finally
        {
            _changingStartup = false;
            UpdateGuardianStatus();
            UpdateActionButtons();
        }
    }

    private async Task StartTargetAsync()
    {
        if (_starting)
        {
            return;
        }

        _starting = true;
        UpdateActionButtons();
        try
        {
            await RefreshStateAsync(rediscover: true);

            if (_targetApplication is null)
            {
                WpfMessageBox.Show(this,
                    _targetDiscovery.Status == "NotFound"
                        ? "没有发现已安装的 ChatGPT Windows 应用。"
                        : "当前无法安全确认 ChatGPT 安装位置，请检查应用包权限后刷新。 " + _targetDiscovery.Detail,
                    "无法启动", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var launch = _targetService.Start(_targetApplication);
            _lastLaunchResult = launch;
            AddEvent($"已请求 Windows 应用入口打开 ChatGPT，PID {launch.ProcessId}；此快捷操作没有修改代理配置、环境变量或启动参数。");
            FooterStatusText.Text = "已请求 Windows 打开 ChatGPT；代理保护由后台 Guardian/ProxiFyre 状态决定。";
            await Task.Delay(900);
            await RefreshStateAsync();
        }
        catch (Exception ex)
        {
            ShowError("启动 ChatGPT 失败", ex);
        }
        finally
        {
            _starting = false;
            UpdateActionButtons();
        }
    }

    private async Task StopTargetAsync()
    {
        if (_stopping)
        {
            return;
        }

        if (_targetApplication is null)
        {
            WpfMessageBox.Show(this, "没有发现已安装的 ChatGPT Windows 应用。", "无法关闭", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        _stopping = true;
        UpdateActionButtons();
        try
        {
            var target = _targetApplication;
            var result = await _targetService.RequestGracefulStopAsync(target, TimeSpan.FromSeconds(5));
            if (!result.HadRunningInstance || result.RemainingRootProcessIds.Count == 0)
            {
                AddEvent("ChatGPT 已正常关闭。");
                await RefreshStateAsync();
                return;
            }

            var answer = WpfMessageBox.Show(
                this,
                $"ChatGPT 尚未正常退出（根进程 PID：{string.Join(", ", result.RemainingRootProcessIds)}）。\n\n强制结束会关闭这些 ChatGPT 实例及其子进程，并可能中断正在进行的对话或 Codex 工作。是否强制结束？",
                "确认强制关闭 ChatGPT",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (answer == MessageBoxResult.Yes)
            {
                var errors = await Task.Run(() => _targetService.ForceStop(target, result.RemainingRootProcessIds));
                AddEvent(errors.Count == 0
                    ? "已请求强制结束仍在运行的 ChatGPT 目标进程树。"
                    : "强制关闭未完全成功：" + string.Join("；", errors));
                if (errors.Count > 0)
                {
                    WpfMessageBox.Show(this, string.Join(Environment.NewLine, errors), "部分进程无法关闭", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
            else
            {
                AddEvent("用户取消强制关闭；仍运行的进程已保留。");
            }

            await RefreshStateAsync();
        }
        catch (Exception ex)
        {
            ShowError("关闭 ChatGPT 失败", ex);
        }
        finally
        {
            _stopping = false;
            UpdateActionButtons();
        }
    }

    private async Task RefreshStateAsync(bool rediscover = false)
    {
        if (_refreshing)
        {
            return;
        }

        _refreshing = true;
        try
        {
            if (rediscover || _targetApplication is null)
            {
                _targetApplication = null;
                _targetDiscovery = await Task.Run(() => _targetService.DiscoverInstalled(_settings?.SelectedPackageFullName));
                _targetApplication = _targetDiscovery.Application;
                _updatingTargetChoices = true;
                var choices = _targetDiscovery.Candidates ?? Array.Empty<TargetApplication>();
                TargetChoiceCombo.ItemsSource = choices.Select(application => new TargetChoiceItem(
                    application,
                    $"v{application.Version} · {Path.GetFileName(application.InstallLocation)}")).ToArray();
                var distinctPackageFamilies = choices.Select(application => application.PackageFamilyName)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Take(2)
                    .Count();
                TargetChoiceCombo.Visibility = distinctPackageFamilies > 1 ? Visibility.Visible : Visibility.Collapsed;
                if (distinctPackageFamilies > 1 && _targetApplication is null)
                {
                    AdvancedSection.IsExpanded = true;
                    ApplicationSection.IsExpanded = true;
                }
                TargetChoiceCombo.SelectedItem = _targetApplication is null
                    ? null
                    : TargetChoiceCombo.Items.Cast<TargetChoiceItem>().FirstOrDefault(item =>
                        string.Equals(item.Application.PackageFullName, _targetApplication.PackageFullName, StringComparison.OrdinalIgnoreCase));
                _updatingTargetChoices = false;
                if (_targetApplication is null)
                {
                    var notFound = _targetDiscovery.Status == "NotFound";
                    var selectionRequired = _targetDiscovery.Status == "SelectionRequired";
                    AppStatusText.Text = notFound ? "未找到应用" : selectionRequired ? "需要选择安装" : "安装状态未知";
                    ProcessSummaryText.Text = notFound
                        ? "请确认已安装 ChatGPT Windows 桌面应用。"
                        : selectionRequired ? "发现多个 ChatGPT 安装，请从下拉框中明确选择。" : "包注册、安装路径或清单暂时无法安全确认。";
                    TargetInfoText.Text = notFound
                        ? "未发现受支持的 OpenAI.Codex MSIX 应用包。"
                        : selectionRequired ? _targetDiscovery.Detail ?? "请先选择实际使用的安装。"
                        : "目标状态 Unknown：" + (_targetDiscovery.Detail ?? "无法安全读取安装信息。");
                    ScopeSummaryText.Text = notFound
                        ? "没有目标安装信息，因此不会生成任何代理规则。"
                        : selectionRequired ? "尚未选择目标包，因此不会生成代理规则或启动应用。"
                        : "安装发现状态未知，启动和规则生成已停用；请修复权限或安装后重新发现。";
                    _runtime = new TargetRuntimeSnapshot(DateTimeOffset.Now, Array.Empty<TargetInstance>());
                    _proxyEngineStatus = await Task.Run(ProxyEngineService.GetStatus);
                    _connections.Clear();
                    ConnectionCountText.Text = "0 条连接";
                    RouteStatusText.Text = notFound ? "未观察到目标连接" : selectionRequired ? "等待用户选择安装" : "目标连接状态未知";
                    LastRefreshText.Text = DateTime.Now.ToString("HH:mm:ss");
                    UpdateGuardianStatus();
                    UpdateActionButtons();
                    return;
                }

                TargetInfoText.Text = DescribeTargetIdentity(_targetApplication);
                ScopeSummaryText.Text = DescribeTargetScope(_targetApplication);
                AddEvent($"已发现 {_targetApplication.DisplayName} {_targetApplication.Version}，审核范围内 EXE 数量 {_targetApplication.RuleExecutablePaths.Count}。");
            }

            var target = _targetApplication!;
            var captured = await Task.Run(() =>
            {
                var runtime = _targetService.CaptureRuntime(target);
                var observation = _connectionObserver.Capture(runtime);
                var engineStatus = ProxyEngineService.GetStatus();
                return (runtime, observation, engineStatus);
            });

            _runtime = captured.runtime;
            _lastObservation = captured.observation;
            _proxyEngineStatus = captured.engineStatus;
            if (!_proxyEngineStatus.IsRunning
                || _proxyEngineStatus.Driver != "运行中"
                || !_proxyEngineStatus.ConfigurationOwned
                || !_proxyEngineStatus.OfficialBinariesVerified
                || !_proxyEngineStatus.ServicePathVerified)
                _engineReadyEvidenceAt = null;
            var instanceCount = _runtime.Instances.Count;
            var componentProcessCount = _runtime.KnownComponentProcesses.Count;
            AppStatusText.Text = instanceCount > 0 ? "运行中" : componentProcessCount > 0 ? "后台组件运行中" : "未运行";
            ProcessSummaryText.Text = instanceCount == 0
                ? componentProcessCount == 0 ? "可以从 Windows 正常打开应用" : $"{componentProcessCount} 个后台组件运行中"
                : $"{instanceCount} 个实例 · {componentProcessCount} 个已识别组件";
            UpdateGuardianStatus();

            _connections.Clear();
            foreach (var connection in captured.observation.Connections)
            {
                _connections.Add(connection);
            }

            ConnectionCountText.Text = $"{_connections.Count} 条连接";
            LastRefreshText.Text = $"连接观察采样 {captured.observation.CapturedAt.ToLocalTime():HH:mm:ss}";
            UpdateRouteStatus(captured.observation, instanceCount);
            UpdateActionButtons();
            FooterStatusText.Text = $"状态更新 {DateTime.Now:HH:mm:ss}";
        }
        catch (Exception ex)
        {
            if (rediscover)
            {
                _targetApplication = null;
                _targetDiscovery = new TargetDiscoveryResult(null, "Unknown", "安装发现异常：" + ex.GetType().Name);
                _runtime = new TargetRuntimeSnapshot(DateTimeOffset.Now, Array.Empty<TargetInstance>());
                UpdateActionButtons();
            }
            FooterStatusText.Text = "状态刷新失败：" + ex.Message;
            AddEvent("状态刷新失败：" + ex.Message);
        }
        finally
        {
            _refreshing = false;
            UpdateProxySummary();
            UpdateActionButtons();
        }
    }

    private void UpdateRouteStatus(ConnectionObservation observation, int instanceCount)
    {
        UpdateGuardianStatus();
        var summary = RouteStatusText.Text;
        if (!string.Equals(_lastRouteSummary, summary, StringComparison.Ordinal))
        {
            _lastRouteSummary = summary;
            AddEvent($"保护状态：{summary}。真实客户端连接验收见高级诊断。");
        }
    }

    private void UpdateGuardianStatus()
    {
        var guardian = GuardianStatusReader.Read();
        var presentation = ProtectionPresentation.From(guardian, StartupCheckBox.IsChecked == true);
        if (guardian.State == "Ready" && _currentEndpoint is not null && _targetApplication is not null
            && ProxyEngineService.VerifyCurrentRules(_currentEndpoint, _targetApplication.RuleExecutablePaths).Status != "Pass")
            presentation = new ProtectionPresentation("保护范围需要更新", "发现客户端后台路径未被当前规则覆盖。保存工作并关闭 Codex 后，点击“准备 / 修复保护”。", "Warning");
        if (guardian.State == "NeedsRepair" && guardian.Detail.StartsWith("后台版本", StringComparison.Ordinal))
            presentation = new ProtectionPresentation("后台版本需要更新", guardian.Detail, "Warning");
        if (!guardian.IsLive && _proxyEngineStatus is { IsRunning: true, ConfigurationOwned: true,
                OfficialBinariesVerified: true, ServicePathVerified: true, Driver: "运行中" }
            && _currentEndpoint is not null && _targetApplication is not null
            && ProxyEngineService.VerifyCurrentRules(_currentEndpoint, _targetApplication.RuleExecutablePaths).Status == "Pass")
            presentation = new ProtectionPresentation("保护组件已准备，后台待启动", StartupCheckBox.IsChecked == true
                ? "登录任务已启用但后台尚未运行。请取消后重新勾选下方选项，启动后台；无需重复安装组件。"
                : "勾选下方“Windows 登录后自动准备保护”启动后台。后台就绪后才能确认持续保护。", "Warning");
        if (_currentEndpoint is null)
            presentation = new ProtectionPresentation("先设置代理地址", "展开下方连接设置，填写代理地址与端口，然后检测并准备保护。", "Warning");
        RouteStatusText.Text = presentation.Title;
        LastRefreshText.Text = presentation.NextAction;
        ProtectionBanner.SetResourceReference(System.Windows.Controls.Border.BackgroundProperty,
            presentation.Tone == "Ready" ? "AccentSoftBrush" : presentation.Tone == "Warning" ? "WarningSoftBrush" : "SurfaceBrush");
        ProtectionIndicator.SetResourceReference(System.Windows.Shapes.Shape.FillProperty,
            presentation.Tone == "Ready" ? "AccentBrush" : presentation.Tone == "Warning" ? "WarningBrush" : "MutedBrush");
        RouteStatusText.SetResourceReference(System.Windows.Controls.TextBlock.ForegroundProperty,
            presentation.Tone == "Ready" ? "AccentTextBrush" : presentation.Tone == "Warning" ? "WarningBrush" : "TextBrush");
        LauncherStatusText.Text = guardian.DisplayText;
        var addressFamily = guardian.IsLive && guardian.CurrentRulesStatus?.StartsWith("Pass", StringComparison.OrdinalIgnoreCase) == true
            ? "IPv4/IPv6 规则已核验；实际客户端流量 Unknown"
            : "IPv4/IPv6 规则与实际流量 Unknown";
        ProtectionDetailsText.Text = $"Guardian 心跳：{guardian.CapturedAt?.ToLocalTime().ToString("MM-dd HH:mm:ss") ?? "未收到"} · 持续运行：{guardian.IsLive}{Environment.NewLine}SOCKS5：{guardian.ProxyEndpoint ?? "未配置"} · {guardian.ProxyEndpointType ?? "Unknown"}/{guardian.Socks5Status ?? "Unknown"}{Environment.NewLine}ProxiFyre：{guardian.ServiceStatus ?? "Unknown"} · 驱动：{guardian.DriverStatus ?? "Unknown"}{Environment.NewLine}规则：{guardian.CurrentRulesStatus ?? "Unknown"} · {addressFamily}";
        ClientValidationText.Text = $"Responses WSS：{_lastCodexLogEvidence?.ResponsesStatus ?? "NotTested"}{Environment.NewLine}Remote Control：{_lastCodexLogEvidence?.RemoteStatus ?? "NotTested"}" +
            (_lastCodexLogEvidence is null ? "\n未导入客户端日志" : $"\n日志修改时间：{_lastCodexLogEvidence.FileModifiedAt.ToLocalTime():MM-dd HH:mm}");
        // Keep these conclusions visible in details, separate from control-plane Ready.
        ProtectionContinuityText.Text = guardian.IsLive && guardian.State == "Ready"
            ? "后台守护与代理服务正常时，退出界面后保护仍会继续。"
            : "后台就绪后可独立提供保护；当前尚未确认可持续保护。";
    }

    private string BuildDiagnosticsReport(NetworkDiagnosticsSnapshot networkDiagnostics, IReadOnlyList<string> recentEngineLogs)
    {
        var report = new StringBuilder();
        report.AppendLine("Codex 代理管理器 · 无感透明代理v1.6 by 豆馅 诊断报告");
        report.AppendLine($"导出时间：{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}");
        report.AppendLine($"管理器版本：{Assembly.GetEntryAssembly()?.GetName().Version?.ToString() ?? "未知"}");
        report.AppendLine($"Windows：{Environment.OSVersion.VersionString}");
        report.AppendLine($"目标应用：{_targetApplication?.DisplayName ?? "未发现"}");
        report.AppendLine($"目标安装发现状态：{_targetDiscovery.Status} · {_targetDiscovery.Detail ?? "无"}");
        report.AppendLine($"应用版本：{_targetApplication?.Version ?? "未知"}");
        report.AppendLine($"安装类型：{(_targetApplication is null ? "未知" : "MSIX")}");
        report.AppendLine($"包标识：{_targetApplication?.PackageFullName ?? "未知"}");
        report.AppendLine($"PackageFamilyName：{_targetApplication?.PackageFamilyName ?? "未知"}");
        report.AppendLine($"Publisher：{_targetApplication?.Publisher ?? "未知"}");
        report.AppendLine($"PublisherDisplayName：{_targetApplication?.PublisherDisplayName ?? "未知"}");
        report.AppendLine($"AUMID：{_targetApplication?.AppUserModelId ?? "未知"}");
        report.AppendLine($"系统代理状态：{_systemProxy?.ModeDescription ?? "未知"}");
        report.AppendLine($"系统代理端点：{_systemProxy?.Endpoint?.Display ?? "未识别"}");
        report.AppendLine($"系统代理绕过项数量：{_systemProxy?.BypassCount.ToString() ?? "未知"}");
        report.AppendLine($"当前 SOCKS5 端点：{_currentEndpoint?.Display ?? "未配置"}");
        report.AppendLine($"最近 SOCKS5 CONNECT/TLS 探测：{_lastSocksProbeAt?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") ?? "NotTested"} · 端点 {_lastSocksProbeEndpoint?.Display ?? "Unknown"} · 目标 api.openai.com:443 · 阶段 {_lastSocksProbeResult?.Stage ?? "NotTested"} · 结果 {_lastSocksProbeResult?.Success.ToString() ?? "Unknown"} · TLS {_lastSocksProbeResult?.TlsProtocol ?? "Unknown"}");
        report.AppendLine($"进程过滤服务：{_proxyEngineStatus.Service}");
        report.AppendLine($"Windows Packet Filter 驱动：{_proxyEngineStatus.Driver}");
        report.AppendLine($"SCM 服务路径核验：{(_proxyEngineStatus.ServicePathVerified ? "Pass" : "Unknown/Fail")}");
        report.AppendLine($"官方二进制哈希核验：{(_proxyEngineStatus.OfficialBinariesVerified ? "Pass" : "Unknown/Fail")}");
        report.AppendLine($"配置所有权：{_proxyEngineStatus.ConfigurationState}");
        report.AppendLine($"配置 SHA-256：{_proxyEngineStatus.ConfigurationSha256 ?? "Unknown"}");
        var guardian = GuardianStatusReader.Read();
        report.AppendLine($"Guardian 状态：{guardian.State} · {guardian.Detail}");
        var guardianExe = Path.Combine(AppContext.BaseDirectory, "CodexProxyGuardian.exe");
        var guardianVersion = File.Exists(guardianExe)
            ? System.Diagnostics.FileVersionInfo.GetVersionInfo(guardianExe).ProductVersion ?? "未知"
            : "未随管理器目录发现 Guardian 文件";
        report.AppendLine($"Guardian 文件版本：{guardianVersion}");
        report.AppendLine($"Guardian 最近快照：{guardian.CapturedAt?.ToString("yyyy-MM-dd HH:mm:ss 'UTC'") ?? "Unknown"} · 实时进程确认：{(guardian.IsLive ? "Pass" : "Fail/NotRunning")}");
        report.AppendLine($"Guardian 端点类型：{guardian.ProxyEndpointType ?? "Unknown/NotTested"}");
        report.AppendLine($"Guardian SOCKS5：{guardian.Socks5Status ?? "Unknown/NotTested"} · ProxiFyre：{guardian.ServiceStatus ?? "Unknown"} · 驱动：{guardian.DriverStatus ?? "Unknown"} · 当前规则：{guardian.CurrentRulesStatus ?? "Unknown/NotTested"}");
        report.AppendLine($"本轮引擎初始化证据：{_engineReadyEvidenceAt?.ToString("yyyy-MM-dd HH:mm:ss 'UTC'") ?? "Unknown / NotTested"}");
        report.AppendLine("生产引擎：官方 wiresock/proxifyre v2.6.1；候选只使用已核验发布二进制。首次安装仍需官方在线安装器、UAC 与必要时重启。");
        report.AppendLine($"打开入口：{_lastLaunchResult?.Method ?? "本轮未由管理器触发"}");
        report.AppendLine("Windows 激活：使用已发现 MSIX 的 AUMID 调用 Windows 应用激活接口；不创建包上下文辅助进程。");
        report.AppendLine("快捷入口不写代理配置，不添加 HTTP_PROXY/HTTPS_PROXY/ALL_PROXY，不添加 Chromium 代理参数，也不负责启动或配置 ProxiFyre。");
        report.AppendLine("当前代理保护：由独立 Guardian 与 ProxiFyre 后台状态决定；Guardian 会在已安装、已拥有且验证通过的受管引擎上有界地准备/启动，不会静默安装驱动或接管外部配置。");
        report.AppendLine("规则范围：已审核的 MSIX 网络组件，以及由当前包资源描述指纹确定且核验的后台缓存 EXE；使用具体完整路径，不是 PID/进程树隔离。未生成泛化目录或同名 codex.exe 规则。");
        if (_targetApplication is not null)
        {
            report.AppendLine("已发现的客户端与后台组件：");
            foreach (var component in _targetApplication.KnownComponents)
                report.AppendLine($"  {(component.IncludedInRule ? "纳入候选规则" : "仅诊断，不纳入规则")} · {component.RelativePath} · {component.Role} · 依据：{component.Evidence}");
            foreach (var path in _targetApplication.RuleExecutablePaths)
                report.AppendLine("  appNames: " + path);
        }
        report.AppendLine("系统/用户持久环境变量与 Windows 系统代理：未修改。");
        report.AppendLine($"最近导入 Codex 日志时间：{_lastCodexLogEvidence?.FileModifiedAt.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") ?? "未导入"}");
        report.AppendLine($"Responses WSS 日志证据：{_lastCodexLogEvidence?.ResponsesStatus ?? "Unknown / NotTested"}");
        report.AppendLine($"Remote Control WebSocket 日志证据：{_lastCodexLogEvidence?.RemoteStatus ?? "Unknown / NotTested"}；手机端到端：NotTested");
        report.AppendLine("当前网络与 DNS 诊断（只读；查询使用 Windows 当前系统 resolver）：");
        report.Append(networkDiagnostics.Format());
        report.AppendLine("SOCKS5 探测只记录对 api.openai.com:443 的协议/TLS 检查；它不代表当前每条 Codex 目标连接均已通过 SOCKS5 CONNECT。");
        report.AppendLine("限制：日志分类不等于当前授权请求或 Remote 端到端通过；Windows DNS Client、IPv6 分片 UDP、无法归属进程及引擎停机直连边界仍存在。第一版没有持久 Kill Switch。");
        report.AppendLine();

        report.AppendLine("目标进程：");
        if (_runtime is null || _runtime.Instances.Count == 0)
        {
            report.AppendLine("  未观察到运行中的目标实例。");
        }
        else
        {
            foreach (var instance in _runtime.Instances)
            {
                report.AppendLine($"  根 PID {instance.RootProcessId}，共 {instance.Processes.Count} 个进程；启动来源不用于推断代理命中。");
                foreach (var process in instance.Processes)
                {
                    report.AppendLine($"    {process.Name} PID={process.ProcessId} PPID={process.ParentProcessId} image={FormatProcessImage(_targetApplication!, process.ImagePath)} ruleExactPath={(process.ExactRuleTargetPath ? "Yes" : "No/Unknown")}");
                    if (IsSharedProcessName(process.Name))
                        report.AppendLine("      发现 Codex 进程树中的共享子进程；当前 ProxiFyre 路径规则无法按 PID 或父子关系区分其他同名实例，因此未将其加入规则。");
                }
            }
        }

        report.AppendLine("当前 Codex PFN 下的已知组件进程或精确镜像路径匹配（仅诊断，不改变代理规则）：");
        if (_runtime?.KnownComponentProcesses.Count > 0)
        {
            foreach (var process in _runtime.KnownComponentProcesses)
                report.AppendLine($"  {process.Name} PID={process.ProcessId} PPID={process.ParentProcessId} image={FormatProcessImage(_targetApplication!, process.ImagePath)} ruleExactPath={(process.ExactRuleTargetPath ? "Yes" : "No")}");
        }
        else
        {
            report.AppendLine("  当前没有精确路径匹配到已知客户端或后台组件进程。");
        }

        report.AppendLine();
        report.AppendLine("最近连接采样：");
        report.AppendLine($"  采样时间：{_lastObservation?.CapturedAt.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") ?? "无"}");
        report.AppendLine($"  应用 TCP/UDP 连接记录：{_lastObservation?.Connections.Count ?? 0} 条；这些是 Windows 套接字表快照，不等于代理出口流量");
        if (_lastObservation is null || _lastObservation.Connections.Count == 0)
        {
            report.AppendLine("  无连接记录。");
        }
        else
        {
            foreach (var connection in _lastObservation.Connections)
            {
                report.AppendLine($"  {connection.ProcessName} PID={connection.ProcessId} {connection.Protocol} {connection.Endpoint} [{connection.State}] {connection.Route}");
                report.AppendLine($"    首次/最近观察：{connection.ObservedTime}；依据：{connection.Evidence}");
            }
        }

        report.AppendLine();
        report.AppendLine("最近 ProxiFyre 引擎日志（仅服务路径和配置所有权核验通过后读取，最多 120 行；敏感字段已脱敏）：");
        foreach (var line in recentEngineLogs)
            report.AppendLine("  " + line);

        report.AppendLine();
        report.AppendLine("最近事件：");
        foreach (var entry in _events)
        {
            report.AppendLine("  " + entry);
        }

        report.AppendLine();
        report.AppendLine("说明：报告不包含代理认证信息、Cookie、Token 或请求正文；网卡/连接快照可能包含本地地址、远端 IP/端口、进程 ID 和网卡名称。分享前请检查。套接字表只能提供观察线索，不能证明所有连接都经代理。");
        return string.Join(Environment.NewLine, report.ToString().Split(Environment.NewLine)
            .Select(ProxyEngineService.RedactEngineLogLine));
    }

    private bool SaveCurrentProxy(bool followSystem)
    {
        if (!TryReadCurrentEndpoint(out var error))
        {
            ProxyEditHintText.Text = error;
            ProxyEditHintText.SetResourceReference(System.Windows.Controls.TextBlock.ForegroundProperty, "DangerBrush");
            WpfMessageBox.Show(this, error, "代理配置无效", MessageBoxButton.OK, MessageBoxImage.Warning);
            return false;
        }

        try
        {
            var endpoint = _currentEndpoint!;
            _settings = (_settings ?? new AppSettings(false, null, null, false)) with
            {
                FollowSystemProxy = followSystem,
                CustomHost = endpoint.Host,
                CustomPort = endpoint.Port,
                RunAtLogon = StartupCheckBox.IsChecked == true
            };
            _settingsStore.Save(_settings);
            _proxyInputDirty = false;
            ProxyEditHintText.Text = $"已保存端点 {endpoint.Display}；Guardian 会验证 SOCKS5 协议。保存不会修改 Windows 系统代理。";
            ProxyEditHintText.SetResourceReference(System.Windows.Controls.TextBlock.ForegroundProperty, "MutedBrush");
            UpdateProxySummary();
            UpdateActionButtons();
            return true;
        }
        catch (Exception ex)
        {
            ShowError("保存代理配置失败", ex);
            return false;
        }
    }

    private bool TryReadCurrentEndpoint(out string error)
    {
        var valid = ProxyEndpoint.TryCreate(ProxyHostBox.Text, ProxyPortBox.Text, out var endpoint, out error);
        _currentEndpoint = valid ? endpoint : null;
        return valid;
    }

    private static string DescribeTargetIdentity(TargetApplication target) =>
        $"版本 {target.Version} · Microsoft Store / MSIX";

    private static string DescribeTargetScope(TargetApplication target)
    {
        var routed = string.Join("、", target.KnownComponents
            .Where(component => component.IncludedInRule)
            .Select(component => component.RelativePath));
        var diagnosticOnly = string.Join("、", target.KnownComponents
            .Where(component => !component.IncludedInRule)
            .Select(component => component.RelativePath));
        return $"包：{target.PackageFullName}{Environment.NewLine}PFN：{target.PackageFamilyName}{Environment.NewLine}发布者：{target.Publisher}{Environment.NewLine}安装目录：{target.InstallLocation}{Environment.NewLine}候选代理规则目标：{(routed.Length == 0 ? "无" : routed)}{Environment.NewLine}仅诊断、不代理：{(diagnosticOnly.Length == 0 ? "无已知组件" : diagnosticOnly)}。共享子进程不会按 PID 自动加入规则。";
    }

    private static bool IsSharedProcessName(string processName) => processName.ToLowerInvariant() is
        "python.exe" or "pythonw.exe" or "node.exe" or "git.exe" or "powershell.exe" or "pwsh.exe"
        or "cmd.exe" or "wsl.exe" or "svchost.exe" or "rundll32.exe";

    private static string FormatProcessImage(TargetApplication target, string? imagePath)
    {
        if (string.IsNullOrWhiteSpace(imagePath))
            return "路径未知";

        try
        {
            var fullPath = Path.GetFullPath(imagePath);
            var knownCache = target.KnownComponents.FirstOrDefault(component =>
                component.RelativePath.StartsWith("运行缓存/", StringComparison.Ordinal)
                && string.Equals(component.FullPath, fullPath, StringComparison.OrdinalIgnoreCase));
            if (knownCache is not null) return knownCache.RelativePath;
            var relative = Path.GetRelativePath(target.InstallLocation, fullPath);
            var isWithinPackage = !Path.IsPathRooted(relative)
                && !relative.Equals("..", StringComparison.Ordinal)
                && !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal)
                && !relative.StartsWith(".." + Path.AltDirectorySeparatorChar, StringComparison.Ordinal);
            return isWithinPackage ? "包内\\" + relative : "包外路径（已省略）";
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or NotSupportedException)
        {
            return "路径无法规范化";
        }
    }

    private void UpdateProxySummary()
    {
        ProxyStatusText.Text = _currentEndpoint is null
            ? "未配置可用代理"
            : _currentEndpoint.Display;

        var systemText = _systemProxy is null
            ? "系统代理状态未知"
            : _systemProxy.Endpoint is null
                ? $"系统代理：{_systemProxy.ModeDescription}"
                : $"系统代理：{_systemProxy.ModeDescription} {_systemProxy.Endpoint.Display}；过滤服务将该地址按 SOCKS5 使用，请确认该端口支持 SOCKS5";
        if (_systemProxy?.HasCredentials == true)
        {
            systemText += "；系统配置含认证信息，本程序仅读取主机和端口";
        }

        var source = _proxyInputDirty ? "有未保存的修改" : _settings?.FollowSystemProxy == true ? "跟随系统代理" : "自定义代理";
        var guardian = GuardianStatusReader.Read();
        var proxyVerified = guardian.IsLive && guardian.ProxyEndpoint == _currentEndpoint?.Display
            && guardian.Socks5Status?.StartsWith("Pass", StringComparison.OrdinalIgnoreCase) == true;
        ProxySourceText.Text = source + (proxyVerified ? " · 协议已验证" : " · 协议待验证");
        ProxySourceText.ToolTip = systemText;
    }

    private void UpdateActionButtons()
    {
        var valid = _currentEndpoint is not null;
        var installed = _targetApplication is not null;
        var running = (_runtime?.Instances.Count ?? 0) > 0;
        if (StartButton is not null)
        {
            StartButton.IsEnabled = installed && !_refreshing && !_starting && !_applyingProtection && !_changingStartup;
        }

        if (ProbeProxyButton is not null)
            ProbeProxyButton.IsEnabled = _probeCancellation is null && !_applyingProtection && !_changingStartup;
        if (ApplyProxyProtectionButton is not null)
            ApplyProxyProtectionButton.IsEnabled = _targetApplication is not null && _currentEndpoint is not null
                && _probeCancellation is null && !_applyingProtection && !_refreshing && !_changingStartup;
        if (ProxyHostBox is not null) ProxyHostBox.IsEnabled = !_applyingProtection;
        if (ProxyPortBox is not null) ProxyPortBox.IsEnabled = !_applyingProtection;
        if (SaveProxyButton is not null) SaveProxyButton.IsEnabled = !_applyingProtection;
        if (ReloadSystemProxyButton is not null) ReloadSystemProxyButton.IsEnabled = !_applyingProtection;
        if (StartupCheckBox is not null) StartupCheckBox.IsEnabled = !_applyingProtection && !_changingStartup;
        if (UpdateGuardianButton is not null) UpdateGuardianButton.IsEnabled = !_applyingProtection && !_changingStartup && _probeCancellation is null;
        if (CancelProbeButton is not null)
            CancelProbeButton.Visibility = _probeCancellation is null ? Visibility.Collapsed : Visibility.Visible;
        if (OperationProgressText is not null)
            OperationProgressText.Visibility = _applyingProtection || _changingStartup || _probeCancellation is not null
                ? Visibility.Visible : Visibility.Collapsed;
        if (StopProxyServiceButton is not null)
            StopProxyServiceButton.IsEnabled = _targetApplication is not null
                && _runtime is not null
                && _runtime.Instances.Count == 0
                && _runtime.KnownComponentProcesses.Count == 0
                && _proxyEngineStatus.IsRunning
                && _proxyEngineStatus.ConfigurationOwned
                && _proxyEngineStatus.ServicePathVerified
                && !_refreshing && !_starting && !_applyingProtection && !_stopping;

        if (StopButton is not null)
        {
            StopButton.IsEnabled = installed && running && !_refreshing && !_stopping && !_applyingProtection;
        }
    }

    private void AddEvent(string message)
    {
        var safeMessage = Regex.Replace(message, @"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+", "$1[REDACTED]");
        safeMessage = Regex.Replace(safeMessage, @"(?i)(token|password|cookie|authorization)\s*[:=]\s*[^\s,;]+", "$1=[REDACTED]");
        safeMessage = Regex.Replace(safeMessage, @"\bsk-[A-Za-z0-9_-]{8,}\b", "[REDACTED]");
        if (safeMessage.Length > 500) safeMessage = safeMessage[..500] + "…";
        _events.Insert(0, $"{DateTime.Now:HH:mm:ss}  {safeMessage}");
        while (_events.Count > 100)
        {
            _events.RemoveAt(_events.Count - 1);
        }
    }

    private static string ComputeScopeHash(IEnumerable<string> paths)
    {
        var canonical = string.Join("\n", paths.OrderBy(path => path, StringComparer.OrdinalIgnoreCase));
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    private sealed record TargetChoiceItem(TargetApplication Application, string Label);

    private void ShowError(string title, Exception exception)
    {
        AddEvent(title + "：" + exception.Message);
        WpfMessageBox.Show(this, exception.Message, title, MessageBoxButton.OK, MessageBoxImage.Error);
    }

    private void ShowWindow()
    {
        Show();
        if (WindowState == WindowState.Minimized)
        {
            WindowState = WindowState.Normal;
        }

        Activate();
    }

    private void ExitManager()
    {
        _exitRequested = true;
        _refreshTimer.Stop();
        _windowSource?.RemoveHook(WindowMessageHook);
        _trayIcon.Visible = false;
        Close();
        System.Windows.Application.Current.Shutdown();
    }

    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        if (!_exitRequested)
        {
            e.Cancel = true;
            Hide();
            return;
        }

        _refreshTimer.Stop();
        _trayIcon.Visible = false;
        _trayIcon.Dispose();
    }

    private void Window_StateChanged(object? sender, EventArgs e)
    {
        if (WindowState == WindowState.Minimized)
        {
            Hide();
        }
    }
}



