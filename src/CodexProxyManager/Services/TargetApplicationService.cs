using System.IO;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Xml.Linq;
using Microsoft.Win32;

namespace CodexProxyManager.Services;

public sealed record TargetApplication(
    string DisplayName,
    string Version,
    string PackageFullName,
    string PackageFamilyName,
    string ApplicationId,
    string AppUserModelId,
    string InstallLocation,
    string ExecutablePath,
    IReadOnlyList<string> RuleExecutablePaths,
    string Publisher = "",
    string PublisherDisplayName = "",
    IReadOnlyList<TargetExecutableComponent>? Components = null)
{
    public IReadOnlyList<TargetExecutableComponent> KnownComponents => Components ?? Array.Empty<TargetExecutableComponent>();
}

public sealed record TargetExecutableComponent(
    string RelativePath,
    string FullPath,
    string Role,
    bool IncludedInRule,
    string Evidence);

public sealed record TargetDiscoveryResult(
    TargetApplication? Application,
    string Status,
    string? Detail = null,
    IReadOnlyList<TargetApplication>? Candidates = null);
internal sealed record TargetDiscoveryFailure(Version? Version, string Detail);

public sealed record TargetProcess(
    int ProcessId,
    int ParentProcessId,
    string Name,
    string? ImagePath = null,
    bool ExactRuleTargetPath = false);
public sealed record TargetLaunchResult(int ProcessId, string Method);
public sealed record TargetInstance(int RootProcessId, IReadOnlyList<TargetProcess> Processes)
{
    public IReadOnlySet<int> ProcessIds => Processes.Select(process => process.ProcessId).ToHashSet();
}

public sealed record TargetRuntimeSnapshot(
    DateTimeOffset CapturedAt,
    IReadOnlyList<TargetInstance> Instances,
    IReadOnlyList<TargetProcess>? PackageComponentProcesses = null)
{
    public IReadOnlyList<TargetProcess> KnownComponentProcesses => PackageComponentProcesses ?? Array.Empty<TargetProcess>();
}
public sealed record StopAttemptResult(bool HadRunningInstance, IReadOnlyList<int> RemainingRootProcessIds);

public sealed class TargetApplicationService
{
    private const string PackagesRegistryPath =
        @"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages";

    private static readonly (string RelativePath, string Role)[] KnownUnroutedComponents =
    [
        ("app/Codex.exe", "包内组件；当前清单未确认其代理职责"),
        ("app/resources/codex-code-mode-host.exe", "代码模式宿主；当前未确认其网络职责"),
        ("app/resources/codex-windows-sandbox-service.exe", "沙箱服务；当前未确认其网络职责"),
        ("app/resources/codex-windows-sandbox-setup.exe", "沙箱安装/配置工具；当前未确认其网络职责")
    ];

    private const string ConfirmedCodexNetworkExecutable = "app/resources/codex.exe";

    public TargetDiscoveryResult DiscoverInstalled(string? preferredPackageFullName = null)
    {
        RegistryKey? packages;
        try
        {
            packages = Registry.CurrentUser.OpenSubKey(PackagesRegistryPath);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            return new TargetDiscoveryResult(null, "Unknown", "无法读取当前用户的 Windows 应用包注册信息。");
        }

        using (packages)
        {
            if (packages is null)
                return new TargetDiscoveryResult(null, "NotFound", "当前用户没有可读取的应用包注册目录。");

            string[] packageNames;
            try
            {
                packageNames = packages.GetSubKeyNames()
                    .Where(name => name.StartsWith("OpenAI.Codex_", StringComparison.OrdinalIgnoreCase))
                    .ToArray();
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
            {
                return new TargetDiscoveryResult(null, "Unknown", "无法枚举 OpenAI.Codex 应用包注册信息。");
            }

            if (packageNames.Length == 0)
                return new TargetDiscoveryResult(null, "NotFound", "未注册 OpenAI.Codex Windows 应用包。");

            var candidates = new List<TargetApplication>();
            var failures = new List<TargetDiscoveryFailure>();
            foreach (var packageName in packageNames)
            {
                var version = ReadPackageVersion(packageName);
                try
                {
                    using var packageKey = packages.OpenSubKey(packageName);
                    var installLocation = packageKey?.GetValue("PackageRootFolder") as string;
                    if (string.IsNullOrWhiteSpace(installLocation))
                        throw new IOException("注册项缺少安装目录。");

                    installLocation = Path.GetFullPath(installLocation);
                    var windowsApps = Path.GetFullPath(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WindowsApps"))
                        .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
                    var packageDirectory = new DirectoryInfo(installLocation);
                    if (!installLocation.StartsWith(windowsApps, StringComparison.OrdinalIgnoreCase)
                        || !string.Equals(packageDirectory.Name, packageName, StringComparison.OrdinalIgnoreCase)
                        || (packageDirectory.Attributes & FileAttributes.ReparsePoint) != 0)
                        throw new InvalidDataException("注册包路径不在对应的 WindowsApps 安装目录中，或目录是重解析点。");

                    var manifestPath = Path.Combine(installLocation, "AppxManifest.xml");
                    var manifestAttributes = File.GetAttributes(manifestPath);
                    if ((manifestAttributes & FileAttributes.ReparsePoint) != 0)
                        throw new IOException("应用清单是重解析点。");

                    var application = RelocatedBackendDiscovery.Attach(ReadManifest(manifestPath, packageName, installLocation));
                    candidates.Add(application);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException
                                           or System.Xml.XmlException or InvalidDataException or ArgumentException)
                {
                    failures.Add(new TargetDiscoveryFailure(version, $"包 {packageName} 的安装路径或清单无法安全读取（{ex.GetType().Name}）。"));
                }
            }

            return ResolveDiscovery(candidates, failures, preferredPackageFullName);
        }
    }

    internal static TargetDiscoveryResult ResolveDiscovery(
        IReadOnlyCollection<TargetApplication> candidates,
        IReadOnlyCollection<TargetDiscoveryFailure> failures,
        string? preferredPackageFullName = null)
    {
        var ordered = candidates
            .OrderByDescending(candidate => Version.TryParse(candidate.Version, out var version) ? version : new Version())
            .ToArray();
        var newestReadable = ordered.FirstOrDefault();
        var singlePackageFamily = ordered
            .Select(candidate => candidate.PackageFamilyName)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(2)
            .Count() == 1;
        var selected = singlePackageFamily
            ? newestReadable
            : string.IsNullOrWhiteSpace(preferredPackageFullName)
                ? null
                : ordered.FirstOrDefault(candidate => string.Equals(candidate.PackageFullName, preferredPackageFullName, StringComparison.OrdinalIgnoreCase));
        selected ??= ordered.Length == 1 ? ordered[0] : null;
        if (newestReadable is null)
        {
            return failures.Count == 0
                ? new TargetDiscoveryResult(null, "NotFound", "没有找到可用的 OpenAI.Codex 安装清单。")
                : new TargetDiscoveryResult(null, "Unknown", string.Join(" ", failures.Select(item => item.Detail)));
        }

        var newestVersion = Version.TryParse(newestReadable.Version, out var parsed) ? parsed : new Version();
        var relevantFailure = failures.FirstOrDefault(failure => failure.Version is null || failure.Version >= newestVersion);
        if (relevantFailure is not null)
            return new TargetDiscoveryResult(null, "Unknown", relevantFailure.Detail + " 无法确认最新安装，已停用启动入口。", ordered);

        if (selected is null)
        {
            return new TargetDiscoveryResult(null, "SelectionRequired", "发现多个 ChatGPT 安装，请先选择实际使用的包。", ordered);
        }

        return relevantFailure is null
            ? new TargetDiscoveryResult(selected, "Found", Candidates: ordered)
            : new TargetDiscoveryResult(null, "Unknown", relevantFailure.Detail + " 无法确认最新安装，已停用启动入口。", ordered);
    }

    private static Version? ReadPackageVersion(string packageFullName)
    {
        var parts = packageFullName.Split('_');
        return parts.Length > 1 && Version.TryParse(parts[1], out var version) ? version : null;
    }

    public static void VerifyManifestRulePaths(string installLocation, IReadOnlyCollection<string> requestedPaths) =>
        _ = ReadVerifiedManifestTarget(installLocation, requestedPaths);

    internal static TargetApplication ReadVerifiedManifestTarget(string installLocation, IReadOnlyCollection<string> requestedPaths)
    {
        var root = Path.GetFullPath(installLocation).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var windowsApps = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WindowsApps");
        var expectedPackageRoot = Path.GetFullPath(windowsApps).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var packageDirectory = new DirectoryInfo(root);
        if (!root.StartsWith(expectedPackageRoot, StringComparison.OrdinalIgnoreCase)
            || !packageDirectory.Name.StartsWith("OpenAI.Codex_", StringComparison.OrdinalIgnoreCase)
            || !packageDirectory.Name.EndsWith("_2p2nqsd0c76g0", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("管理员辅助程序只接受 WindowsApps 中已签名的 OpenAI.Codex Store 包目录。");

        if ((packageDirectory.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("ChatGPT 包安装目录是重解析点，拒绝生成管理员代理规则。");

        var manifestPath = Path.Combine(root, "AppxManifest.xml");
        if (!File.Exists(manifestPath) || (File.GetAttributes(manifestPath) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("ChatGPT 包清单缺失或不可安全读取。");

        var parsed = ReadManifest(manifestPath, packageDirectory.Name, root);
        var expanded = RelocatedBackendDiscovery.Attach(parsed);
        VerifyRulePathsMatchManifest(expanded, requestedPaths);
        foreach (var path in parsed.RuleExecutablePaths)
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException($"包执行文件是重解析点，拒绝使用：{Path.GetFileName(path)}");
        return expanded;
    }

    internal static void VerifyRulePathsMatchManifest(TargetApplication parsed, IReadOnlyCollection<string> requestedPaths)
    {
        var manifestPaths = parsed.RuleExecutablePaths
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var requested = requestedPaths.Select(Path.GetFullPath).Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase).ToArray();
        if (!manifestPaths.SequenceEqual(requested, StringComparer.OrdinalIgnoreCase))
            throw new InvalidDataException("管理员请求中的执行文件与当前 MSIX 应用及已核实网络声明不一致；请重新发现应用。");
    }

    public TargetRuntimeSnapshot CaptureRuntime(TargetApplication target)
    {
        var processTable = WindowsNativeSnapshot.ReadProcesses();
        var routePaths = target.RuleExecutablePaths.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var imagePathCache = new Dictionary<int, string?>();
        var packageFamilyCache = new Dictionary<int, string?>();
        string? ReadImagePathCached(int processId)
        {
            if (!imagePathCache.TryGetValue(processId, out var imagePath))
                imagePathCache[processId] = imagePath = WindowsNativeSnapshot.ReadImagePath(processId);
            return imagePath;
        }

        string? ReadPackageFamilyCached(int processId)
        {
            if (!packageFamilyCache.TryGetValue(processId, out var packageFamilyName))
                packageFamilyCache[processId] = packageFamilyName = WindowsNativeSnapshot.ReadPackageFamilyName(processId);
            return packageFamilyName;
        }

        var executableName = Path.GetFileName(target.ExecutablePath);
        var candidates = processTable.Values
            .Where(process => string.Equals(process.Name, executableName, StringComparison.OrdinalIgnoreCase))
            .Where(process =>
            {
                var imagePath = ReadImagePathCached(process.ProcessId);
                return string.Equals(imagePath, Path.GetFullPath(target.ExecutablePath), StringComparison.OrdinalIgnoreCase)
                    || (!string.IsNullOrWhiteSpace(target.PackageFamilyName)
                        && string.Equals(ReadPackageFamilyCached(process.ProcessId), target.PackageFamilyName, StringComparison.OrdinalIgnoreCase));
            })
            .ToDictionary(process => process.ProcessId);

        var roots = candidates.Values
            .Where(process => !candidates.ContainsKey(process.ParentProcessId))
            .OrderBy(process => process.ProcessId)
            .ToArray();

        var instances = new List<TargetInstance>();
        foreach (var root in roots)
        {
            var ids = GetDescendantPids(root.ProcessId, processTable);
            var related = ids
                .Where(processTable.ContainsKey)
                .Select(processId => processTable[processId])
                .OrderBy(process => process.ProcessId)
                .Select(process =>
                {
                    var imagePath = ReadImagePathCached(process.ProcessId);
                    return new TargetProcess(
                        process.ProcessId,
                        process.ParentProcessId,
                        process.Name,
                        imagePath,
                        imagePath is not null && routePaths.Contains(Path.GetFullPath(imagePath)));
                })
                .ToArray();
            instances.Add(new TargetInstance(root.ProcessId, related));
        }

        var allKnownComponents = target.KnownComponents
            .Concat(target.RuleExecutablePaths.Select(path => new TargetExecutableComponent(
                Path.GetRelativePath(target.InstallLocation, path).Replace(Path.DirectorySeparatorChar, '/'),
                Path.GetFullPath(path),
                "当前审核通过的 ProxiFyre 规则目标",
                true,
                "规则路径来自已发现的 MSIX 目标；此 PID 识别仅用于诊断，不提供引擎命中证明。")))
            .GroupBy(component => Path.GetFullPath(component.FullPath), StringComparer.OrdinalIgnoreCase)
            .Select(group => group.FirstOrDefault(component => component.IncludedInRule) ?? group.First())
            .ToArray();
        var knownPaths = allKnownComponents
            .GroupBy(component => Path.GetFileName(component.FullPath), StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.ToArray(), StringComparer.OrdinalIgnoreCase);
        var componentProcesses = new List<TargetProcess>();
        foreach (var process in processTable.Values)
        {
            if (!knownPaths.TryGetValue(process.Name, out var components))
                continue;

            var imagePath = ReadImagePathCached(process.ProcessId);
            if (imagePath is null)
                continue;
            var fullImagePath = Path.GetFullPath(imagePath);
            var component = components.FirstOrDefault(item => string.Equals(
                fullImagePath, Path.GetFullPath(item.FullPath), StringComparison.OrdinalIgnoreCase));
            component ??= !string.IsNullOrWhiteSpace(target.PackageFamilyName)
                && string.Equals(ReadPackageFamilyCached(process.ProcessId), target.PackageFamilyName, StringComparison.OrdinalIgnoreCase)
                    ? components.FirstOrDefault(item => string.Equals(Path.GetFileName(item.FullPath), process.Name, StringComparison.OrdinalIgnoreCase))
                    : null;
            if (component is not null)
                componentProcesses.Add(new TargetProcess(
                    process.ProcessId,
                    process.ParentProcessId,
                    process.Name,
                    fullImagePath,
                    component.IncludedInRule));
        }

        return new TargetRuntimeSnapshot(DateTimeOffset.Now, instances, componentProcesses.OrderBy(process => process.ProcessId).ToArray());
    }

    public IReadOnlyList<string> ReadAccessibleProcessImagePaths()
    {
        var paths = new List<string>();
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    if (!string.IsNullOrWhiteSpace(process.MainModule?.FileName))
                        paths.Add(Path.GetFullPath(process.MainModule!.FileName));
                }
                catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException)
                {
                    // Inaccessible processes remain Unknown and are not used to expand scope.
                }
            }
        }

        return paths.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    public TargetLaunchResult Start(TargetApplication target)
    {
        try
        {
            var processId = WindowsApplicationActivator.Activate(target);
            return new TargetLaunchResult(processId, "Windows AUMID 应用激活（与开始菜单相同的应用入口）");
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"通过 Windows 应用入口打开 ChatGPT 失败：{ex.Message}",
                ex);
        }
    }

    public async Task<StopAttemptResult> RequestGracefulStopAsync(TargetApplication target, TimeSpan timeout)
    {
        var before = CaptureRuntime(target);
        if (before.Instances.Count == 0)
        {
            return new StopAttemptResult(false, Array.Empty<int>());
        }

        foreach (var instance in before.Instances)
        {
            try
            {
                using var process = Process.GetProcessById(instance.RootProcessId);
                process.CloseMainWindow();
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                // The process may have exited while its window was being closed.
            }
        }

        await Task.Delay(timeout);
        var after = CaptureRuntime(target);
        return new StopAttemptResult(true, after.Instances.Select(instance => instance.RootProcessId).ToArray());
    }

    public IReadOnlyList<string> ForceStop(TargetApplication target, IReadOnlyCollection<int> requestedRootProcessIds)
    {
        var errors = new List<string>();
        var currentRoots = CaptureRuntime(target).Instances
            .Select(instance => instance.RootProcessId)
            .ToHashSet();
        foreach (var processId in requestedRootProcessIds.Distinct())
        {
            if (!currentRoots.Contains(processId) || !IsTargetExecutable(processId, target.ExecutablePath))
            {
                continue;
            }

            try
            {
                using var process = Process.GetProcessById(processId);
                if (process.MainModule?.FileName is not { } currentPath
                    || !string.Equals(Path.GetFullPath(currentPath), Path.GetFullPath(target.ExecutablePath), StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                process.Kill(entireProcessTree: true);
            }
            catch (ArgumentException)
            {
                // It already exited.
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                errors.Add($"PID {processId}: {ex.Message}");
            }
        }

        return errors;
    }

    internal static TargetApplication ReadManifest(string manifestPath, string packageFullName, string installLocation)
    {
        var document = XDocument.Load(manifestPath, LoadOptions.None);
        return ParseManifest(document, packageFullName, installLocation);
    }

    internal static TargetApplication ParseManifest(XDocument document, string packageFullName, string installLocation)
    {
        var identity = document.Descendants().FirstOrDefault(element => element.Name.LocalName == "Identity");
        if (identity is null || !string.Equals((string?)identity.Attribute("Name"), "OpenAI.Codex", StringComparison.Ordinal))
            throw new InvalidDataException("安装清单身份不是 OpenAI.Codex。");

        var root = Path.GetFullPath(installLocation).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var publisher = (string?)identity.Attribute("Publisher");
        if (string.IsNullOrWhiteSpace(publisher))
            throw new InvalidDataException("应用清单缺少 Publisher 身份。");

        var packageParts = packageFullName.Split('_');
        var packageVersion = packageParts.Length > 1 ? packageParts[1] : string.Empty;
        var version = (string?)identity.Attribute("Version");
        if (packageParts.Length < 2
            || string.IsNullOrWhiteSpace(version)
            || !Version.TryParse(version, out _)
            || !string.Equals(packageParts[0], "OpenAI.Codex", StringComparison.Ordinal)
            || !string.Equals(packageVersion, version, StringComparison.Ordinal))
            throw new InvalidDataException("包全名与清单 Name/Version 不一致。");

        var packageFamilyName = GetPackageFamilyName(packageFullName);
        if (!packageFamilyName.StartsWith("OpenAI.Codex_", StringComparison.Ordinal))
            throw new InvalidDataException("Windows 返回的包族标识与 OpenAI.Codex 不匹配。");

        var appElements = document.Descendants()
            .Where(element => element.Name.LocalName == "Application")
            .Where(element => !string.IsNullOrWhiteSpace((string?)element.Attribute("Executable")))
            .OrderBy(element => string.Equals((string?)element.Attribute("Id"), "App", StringComparison.OrdinalIgnoreCase) ? 0 : 1)
            .ToArray();
        var appElement = appElements.FirstOrDefault();
        if (appElement is null)
            throw new InvalidDataException("应用清单没有声明可执行文件。");

        var applicationId = (string?)appElement.Attribute("Id") ?? "App";
        if (applicationId.Length == 0 || applicationId.Contains('!') || applicationId.Contains('/'))
            throw new InvalidDataException("应用清单中的 Application Id 无效。");
        var executablePath = ResolvePackageExecutable(root, (string?)appElement.Attribute("Executable"));
        var displayName = RegistryDisplayName(packageFullName) ?? "ChatGPT";
        var publisherDisplayName = document.Descendants()
            .FirstOrDefault(element => element.Name.LocalName == "PublisherDisplayName")?.Value?.Trim();
        if (string.IsNullOrWhiteSpace(publisherDisplayName))
            publisherDisplayName = publisher;

        var componentsByPath = new Dictionary<string, TargetExecutableComponent>(StringComparer.OrdinalIgnoreCase);
        void AddComponent(string relativePath, string role, bool included, string evidence)
        {
            var fullPath = ResolvePackageExecutable(root, relativePath);
            if (componentsByPath.TryGetValue(fullPath, out var existing))
            {
                componentsByPath[fullPath] = existing with
                {
                    Role = string.Join("；", new[] { existing.Role, role }.Distinct(StringComparer.Ordinal)),
                    IncludedInRule = existing.IncludedInRule || included,
                    Evidence = string.Join("；", new[] { existing.Evidence, evidence }.Distinct(StringComparer.Ordinal))
                };
            }
            else
            {
                componentsByPath.Add(fullPath, new TargetExecutableComponent(
                    NormalizeRelativePath(relativePath), fullPath, role, included, evidence));
            }
        }

        foreach (var element in appElements)
        {
            var id = (string?)element.Attribute("Id") ?? "(未命名)";
            var relativePath = (string?)element.Attribute("Executable");
            if (string.IsNullOrWhiteSpace(relativePath))
                throw new InvalidDataException("MSIX Application 缺少 Executable 路径。");
            AddComponent(
                relativePath,
                "MSIX Application：" + id,
                included: true,
                evidence: "AppxManifest.xml 明确注册的 Windows 应用入口；规则仍只按该包内完整 EXE 路径匹配。");
        }

        foreach (var firewallRules in document.Descendants().Where(element => element.Name.LocalName == "FirewallRules"))
        {
            var relativePath = (string?)firewallRules.Attribute("Executable");
            if (string.IsNullOrWhiteSpace(relativePath))
                throw new InvalidDataException("应用清单包含缺少 Executable 的 FirewallRules 声明。");

            var normalized = NormalizeRelativePath(relativePath);
            var declaredRules = firewallRules.Elements()
                .Where(element => element.Name.LocalName == "Rule")
                .Select(FormatFirewallRule)
                .ToArray();
            var ruleSummary = declaredRules.Length == 0
                ? "未声明 Rule 子项"
                : string.Join(" | ", declaredRules.Take(16)) + (declaredRules.Length > 16 ? $" | …共 {declaredRules.Length} 条" : string.Empty);
            var roleEvidence = $"AppxManifest FirewallRules 显式网络例外声明：{ruleSummary}；这是防火墙元数据，不是已观察到的出站连接或代理命中证据。";
            var isConfirmedCodexNetworkTarget = string.Equals(normalized, ConfirmedCodexNetworkExecutable, StringComparison.OrdinalIgnoreCase);
            var firewallFullPath = ResolvePackageExecutable(root, normalized);
            var alreadyIncludedByApplication = componentsByPath.TryGetValue(firewallFullPath, out var existingComponent)
                && existingComponent.IncludedInRule;
            AddComponent(
                normalized,
                "MSIX FirewallRules 网络组件",
                included: isConfirmedCodexNetworkTarget || alreadyIncludedByApplication,
                evidence: isConfirmedCodexNetworkTarget
                    ? roleEvidence + " 当前包清单将该精确路径与 Codex 网络端口声明关联；只接受此已确认路径。"
                    : alreadyIncludedByApplication
                        ? roleEvidence + " 此 EXE 已因 MSIX Application 注册进入候选范围；FirewallRules 不扩展规则范围。"
                        : roleEvidence + " 此路径未列入当前已审核路由范围，因此不加入代理规则。");
        }

        foreach (var (relativePath, role) in KnownUnroutedComponents)
        {
            var normalized = NormalizeRelativePath(relativePath);
            var fullPath = Path.GetFullPath(Path.Combine(root, normalized.Replace('/', Path.DirectorySeparatorChar)));
            if (File.Exists(fullPath) && !componentsByPath.ContainsKey(fullPath))
                AddComponent(relativePath, role, included: false, evidence: "仅确认该 EXE 位于当前 MSIX 包中；没有足够证据把它加入 ProxiFyre 路径规则。");
        }

        var components = componentsByPath.Values
            .OrderBy(component => component.RelativePath, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var rulePaths = components
            .Where(component => component.IncludedInRule)
            .Select(component => component.FullPath)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (rulePaths.Length == 0 || !rulePaths.Contains(executablePath, StringComparer.OrdinalIgnoreCase))
            throw new InvalidDataException("主应用 EXE 未进入当前清单确认的代理范围。");

        foreach (var component in components)
        {
            var attributes = File.GetAttributes(component.FullPath);
            if ((attributes & FileAttributes.Directory) != 0 || (attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException($"清单执行文件不是普通 EXE 或为重解析点：{component.RelativePath}");
            if (!string.Equals(Path.GetExtension(component.FullPath), ".exe", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException($"应用清单包含非 EXE 规则目标：{component.RelativePath}");
        }

        return new TargetApplication(
            displayName,
            version,
            packageFullName,
            packageFamilyName,
            applicationId,
            packageFamilyName + "!" + applicationId,
            root,
            executablePath,
            rulePaths,
            publisher,
            publisherDisplayName,
            components);
    }

    private static string ResolvePackageExecutable(string packageRoot, string? relativePath)
    {
        if (string.IsNullOrWhiteSpace(relativePath))
            throw new InvalidDataException("应用清单缺少 EXE 相对路径。");

        var normalized = NormalizeRelativePath(relativePath);
        var nativeRelativePath = normalized.Replace('/', Path.DirectorySeparatorChar);
        var fullPath = Path.GetFullPath(Path.Combine(packageRoot, nativeRelativePath));
        var rootPrefix = packageRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!fullPath.StartsWith(rootPrefix, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(Path.GetExtension(fullPath), ".exe", StringComparison.OrdinalIgnoreCase)
            || !File.Exists(fullPath))
            throw new InvalidDataException("清单 EXE 路径缺失或超出当前 MSIX 安装目录。");

        var attributes = File.GetAttributes(fullPath);
        if ((attributes & FileAttributes.Directory) != 0 || (attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("清单 EXE 不是普通文件或为重解析点。");
        return fullPath;
    }

    private static string NormalizeRelativePath(string relativePath)
    {
        var normalized = relativePath.Trim().Replace('\\', '/');
        var segments = normalized.Split('/', StringSplitOptions.None);
        if (normalized.Length == 0
            || normalized[0] == '/'
            || normalized.Contains(':')
            || segments.Any(segment => segment.Length == 0 || segment is "." or ".."))
            throw new InvalidDataException("清单 EXE 相对路径包含根路径、盘符或路径穿越。");

        return string.Join('/', segments);
    }

    private static string FormatFirewallRule(XElement rule)
    {
        var fields = new[]
        {
            "Direction", "IPProtocol", "LocalPortMin", "LocalPortMax", "RemotePortMin", "RemotePortMax", "Profile"
        };
        var values = fields
            .Select(name => (Name: name, Value: (string?)rule.Attribute(name)))
            .Where(item => !string.IsNullOrWhiteSpace(item.Value))
            .Select(item => item.Name + "=" + item.Value);
        return string.Join(",", values);
    }

    private static string GetPackageFamilyName(string packageFullName)
    {
        uint length = 0;
        var result = PackageFamilyNameFromFullName(packageFullName, ref length, null);
        if (result != ErrorInsufficientBuffer || length is < 2 or > 512)
            throw new InvalidDataException($"Windows 无法从包全名读取 PackageFamilyName（错误 {result}）。");

        var buffer = new StringBuilder(checked((int)length));
        result = PackageFamilyNameFromFullName(packageFullName, ref length, buffer);
        if (result != 0 || buffer.Length == 0)
            throw new InvalidDataException($"Windows 返回 PackageFamilyName 失败（错误 {result}）。");
        return buffer.ToString();
    }

    private const int ErrorInsufficientBuffer = 122;

    [DllImport("kernel32.dll", EntryPoint = "PackageFamilyNameFromFullName", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int PackageFamilyNameFromFullName(string packageFullName, ref uint packageFamilyNameLength, StringBuilder? packageFamilyName);

    private static string? RegistryDisplayName(string packageFullName)
    {
        using var key = Registry.CurrentUser.OpenSubKey(PackagesRegistryPath + "\\" + packageFullName);
        return key?.GetValue("DisplayName") as string;
    }

    private static bool IsTargetExecutable(int processId, string expectedPath)
    {
        var actualPath = WindowsNativeSnapshot.ReadImagePath(processId);
        return actualPath is not null
            && string.Equals(Path.GetFullPath(actualPath), Path.GetFullPath(expectedPath), StringComparison.OrdinalIgnoreCase);
    }

    private static HashSet<int> GetDescendantPids(
        int rootProcessId,
        IReadOnlyDictionary<int, NativeProcessInfo> processes)
    {
        var result = new HashSet<int> { rootProcessId };
        var pending = new Queue<int>();
        pending.Enqueue(rootProcessId);
        while (pending.TryDequeue(out var parentProcessId))
        {
            foreach (var child in processes.Values.Where(process => process.ParentProcessId == parentProcessId))
            {
                if (result.Add(child.ProcessId))
                {
                    pending.Enqueue(child.ProcessId);
                }
            }
        }

        return result;
    }
}
