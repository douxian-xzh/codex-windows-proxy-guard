using System.Diagnostics;
using System.ComponentModel;
using System.IO;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using Microsoft.Win32;

namespace CodexProxyManager.Services;

public static class GuardianTaskInstaller
{
    internal const string HelperArgument = "--guardian-task-admin-helper";
    internal const string TaskName = "\\CodexProxyManagerGuardian";
    private const string TaskUri = TaskName;
    private const string AppDataFolder = "CodexProxyManagerPywBranch";
    private const string RequestFolder = "guardian-setup";
    private const string LegacyRunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string LegacyRunValueName = "CodexProxyManagerPywBranch";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private static readonly string[] EnginePayloadRelativeFiles =
    [
        @"EnginePayload\ProxiFyre-2.6.1-win-x64-setup.exe",
        @"EnginePayload\ProxiFyre-2.6.1-win-x64-setup.exe.sha256",
        @"EnginePayload\ProxiFyre.exe",
        @"EnginePayload\socksify.dll",
        @"EnginePayload\Source\LICENSE",
        @"EnginePayload\Source\README.md",
        @"EnginePayload\Source\proxifyre-v2.6.1-source.zip",
        @"EnginePayload\Source\dependency-lock.json"
    ];

    public static bool IsEnabled()
        => ReadRegisteredTaskVerification().Enabled;

    private static GuardianTaskVerification ReadRegisteredTaskVerification()
    {
        var query = RunSchtasks(["/Query", "/TN", TaskName, "/XML"], allowFailure: true);
        if (query.ExitCode != 0 || string.IsNullOrWhiteSpace(query.StandardOutput))
            return new(false, "未读取到登录任务（查询退出码 " + query.ExitCode + "）。");
        var currentSid = WindowsIdentity.GetCurrent().User?.Value;
        if (currentSid is null) return new(false, "无法确认当前登录用户身份。");
        return VerifyRegisteredTaskXml(query.StandardOutput, currentSid);
    }

    internal static GuardianTaskVerification VerifyRegisteredTaskXml(string xml, string currentSid)
    {
        try
        {
            var document = XDocument.Parse(xml);
            XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
            var task = document.Root;
            if (task?.Name != ns + "Task") return new(false, "任务 XML 根节点无效。");
            if (!string.Equals(task.Element(ns + "RegistrationInfo")?.Element(ns + "URI")?.Value, TaskUri, StringComparison.Ordinal))
                return new(false, "任务所有权标识不匹配。");
            var settings = task.Element(ns + "Settings");
            if (settings is null || !IsXmlEnabled(settings))
                return new(false, "任务已禁用或启用字段无效。");
            var principals = task.Element(ns + "Principals")?.Elements().ToArray() ?? [];
            var triggers = task.Element(ns + "Triggers")?.Elements().ToArray() ?? [];
            var actions = task.Element(ns + "Actions")?.Elements().ToArray() ?? [];
            if (principals.Length != 1 || principals[0].Name != ns + "Principal"
                || triggers.Length != 1 || triggers[0].Name != ns + "LogonTrigger"
                || actions.Length != 1 || actions[0].Name != ns + "Exec")
                return new(false, "任务必须只有一个当前用户登录触发器、权限主体和固定执行动作。");
            var principal = principals[0];
            var trigger = triggers[0];
            var action = actions[0];
            if (!IsCurrentUserIdentity(principal.Element(ns + "UserId")?.Value, currentSid))
                return new(false, "任务执行账户不是当前登录用户或无法解析。");
            if (!IsCurrentUserIdentity(trigger.Element(ns + "UserId")?.Value, currentSid))
                return new(false, "登录触发账户不是当前登录用户或无法解析。");
            if (!IsXmlEnabled(trigger)) return new(false, "登录触发器已禁用。");
            if (principal.Element(ns + "LogonType")?.Value != "InteractiveToken"
                || principal.Element(ns + "RunLevel")?.Value != "HighestAvailable")
                return new(false, "任务交互令牌或最高权限级别不匹配。");
            if (task.Element(ns + "Actions")?.Attribute("Context")?.Value != principal.Attribute("id")?.Value)
                return new(false, "执行动作与权限主体关联不匹配。");
            if (action.Element(ns + "Arguments")?.Value != "--guardian"
                || !IsGuardianPathInInstallRoot(action.Element(ns + "Command")?.Value, GetInstallRoot()))
                return new(false, "任务执行文件或固定参数不匹配。");
            return new(true, "任务所有权、当前用户、登录触发、权限及固定执行路径已核验。");
        }
        catch (Exception ex) when (ex is System.Xml.XmlException or InvalidOperationException or UnauthorizedAccessException
            or ArgumentException or FormatException or System.Security.SecurityException)
        {
            return new(false, "任务定义读取失败（" + ex.GetType().Name + "）。");
        }
    }

    private static bool IsXmlEnabled(XElement parent)
    {
        var elements = parent.Elements(parent.Name.Namespace + "Enabled").ToArray();
        // Task Scheduler omits default=true fields when exporting a registered definition.
        return elements.Length == 0 || (elements.Length == 1 && System.Xml.XmlConvert.ToBoolean(elements[0].Value.Trim()));
    }

    private static bool IsCurrentUserIdentity(string? identity, string currentSid)
    {
        if (string.IsNullOrWhiteSpace(identity)) return false;
        try
        {
            var resolved = identity.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase)
                ? new SecurityIdentifier(identity).Value
                : ((SecurityIdentifier)new NTAccount(identity).Translate(typeof(SecurityIdentifier))).Value;
            return string.Equals(resolved, currentSid, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is IdentityNotMappedException or ArgumentException or System.Security.SecurityException)
        {
            return false;
        }
    }

    public static string? SetEnabled(bool enabled)
    {
        if (enabled)
            _ = GetBundleFiles(AppContext.BaseDirectory);

        var sid = WindowsIdentity.GetCurrent().User?.Value
            ?? throw new InvalidOperationException("无法读取当前登录用户的 SID。");
        var requestDirectory = GetRequestDirectory();
        Directory.CreateDirectory(requestDirectory);
        var token = Guid.NewGuid().ToString("N");
        var requestPath = Path.Combine(requestDirectory, token + ".request.json");
        var responsePath = HelperMessagePaths.ResponseFor(requestPath, ".response.json");
        File.WriteAllText(requestPath, JsonSerializer.Serialize(new GuardianTaskRequest(enabled ? "Register" : "Unregister", sid), JsonOptions), new UTF8Encoding(false));

        Process? helper = null;
        var helperExited = false;
        try
        {
            helper = StartElevatedHelper(requestPath);
            helperExited = helper.WaitForExit(240_000);
            if (!helperExited)
                throw new TimeoutException("后台保护安装助手仍在运行。请稍后刷新状态；系统没有强制终止该助手。");

            var response = File.Exists(responsePath)
                ? JsonSerializer.Deserialize<GuardianTaskResponse>(File.ReadAllText(responsePath), JsonOptions)
                : null;
            if (helper.ExitCode != 0 || response?.Success != true)
                throw new InvalidOperationException(response?.Message ?? $"后台 Guardian 设置失败（助手退出码 {helper.ExitCode}）。");

            RemoveLegacyManagerRunEntry();
            if (IsEnabled() != enabled)
                throw new InvalidOperationException("任务计划程序没有确认当前登录用户的 Guardian 任务状态。");
            return response.Warning;
        }
        finally
        {
            helper?.Dispose();
            if (helperExited)
            {
                TryDelete(requestPath);
                TryDelete(responsePath);
            }
        }
    }

    public static void RemoveLegacyManagerRunEntry()
    {
        using var key = Registry.CurrentUser.OpenSubKey(LegacyRunKeyPath, writable: true);
        key?.DeleteValue(LegacyRunValueName, throwOnMissingValue: false);
    }

    internal static string BuildTaskXml(string userSid, string guardianExecutable)
    {
        SecurityIdentifier sid;
        try { sid = new SecurityIdentifier(userSid); }
        catch (ArgumentException) { throw new InvalidDataException("任务定义中的用户 SID 无效。"); }
        if (!string.Equals(sid.Value, userSid, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("任务定义中的用户 SID 无效。");

        var fullPath = Path.GetFullPath(guardianExecutable);
        if (!IsGuardianPathInInstallRoot(fullPath, GetInstallRoot()))
            throw new InvalidDataException("Guardian 任务只能执行 Program Files 下的固定安装副本。");

        XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
        var task = new XElement(ns + "Task",
            new XAttribute("version", "1.4"),
            new XElement(ns + "RegistrationInfo",
                new XElement(ns + "Author", "Codex 代理管理器"),
                new XElement(ns + "URI", TaskUri),
                new XElement(ns + "Description", "登录后检查 Codex 透明代理保护状态。")),
            new XElement(ns + "Triggers",
                new XElement(ns + "LogonTrigger",
                    new XElement(ns + "Enabled", "true"),
                    new XElement(ns + "UserId", userSid))),
            new XElement(ns + "Principals",
                new XElement(ns + "Principal", new XAttribute("id", "GuardianUser"),
                    new XElement(ns + "UserId", userSid),
                    new XElement(ns + "LogonType", "InteractiveToken"),
                    new XElement(ns + "RunLevel", "HighestAvailable"))),
            new XElement(ns + "Settings",
                new XElement(ns + "MultipleInstancesPolicy", "IgnoreNew"),
                new XElement(ns + "DisallowStartIfOnBatteries", "false"),
                new XElement(ns + "StopIfGoingOnBatteries", "false"),
                new XElement(ns + "StartWhenAvailable", "true"),
                new XElement(ns + "AllowStartOnDemand", "true"),
                new XElement(ns + "ExecutionTimeLimit", "PT0S"),
                new XElement(ns + "Enabled", "true"),
                new XElement(ns + "RestartOnFailure",
                    new XElement(ns + "Interval", "PT1M"),
                    new XElement(ns + "Count", "3"))),
            new XElement(ns + "Actions", new XAttribute("Context", "GuardianUser"),
                new XElement(ns + "Exec",
                    new XElement(ns + "Command", fullPath),
                    new XElement(ns + "Arguments", "--guardian"),
                    new XElement(ns + "WorkingDirectory", Path.GetDirectoryName(fullPath)!))));

        return new XDocument(new XDeclaration("1.0", "UTF-16", null), task)
            .ToString(SaveOptions.DisableFormatting);
    }

    internal static string GetInstallRoot() => Path.GetFullPath(Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "CodexProxyManager", "Guardian"));

    internal static int RunAdminHelper(string requestPath)
    {
        string? responsePath = null;
        try
        {
            var requestDirectory = Path.GetFullPath(GetRequestDirectory());
            requestPath = Path.GetFullPath(requestPath);
            if (!requestPath.StartsWith(requestDirectory + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                || !requestPath.EndsWith(".request.json", StringComparison.OrdinalIgnoreCase)
                || (File.GetAttributes(requestPath) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Guardian 设置请求路径无效。");

            var candidateResponsePath = HelperMessagePaths.ResponseFor(requestPath, ".response.json");
            if (File.Exists(candidateResponsePath) || Directory.Exists(candidateResponsePath))
                throw new InvalidDataException("Guardian 助手结果路径已存在，拒绝覆盖。");
            responsePath = candidateResponsePath;
            var request = JsonSerializer.Deserialize<GuardianTaskRequest>(File.ReadAllText(requestPath), JsonOptions)
                ?? throw new InvalidDataException("Guardian 设置请求内容无效。");
            var currentSid = WindowsIdentity.GetCurrent().User?.Value;
            if (!string.Equals(request.UserSid, currentSid, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("提权助手账户与原登录用户不一致；为避免任务落在错误账户下，已拒绝操作。");

            string? warning = null;
            if (request.Action == "Register")
                warning = RegisterTask(request.UserSid);
            else if (request.Action == "Unregister")
                UnregisterTask();
            else
                throw new InvalidDataException("Guardian 设置请求包含不支持的操作。");

            WriteResponse(responsePath, new GuardianTaskResponse(true, "Guardian 登录任务已更新。", warning));
            return 0;
        }
        catch (Exception ex)
        {
            if (responsePath is not null)
            {
                try { WriteResponse(responsePath, new GuardianTaskResponse(false, ex.Message)); }
                catch (Exception) { }
            }

            return 1;
        }
    }

    private static string? RegisterTask(string userSid)
    {
        var existingTask = RunSchtasks(["/Query", "/TN", TaskName, "/XML"], allowFailure: true);
        if (existingTask.ExitCode == 0 && !IsOwnedTaskXml(existingTask.StandardOutput))
            throw new InvalidOperationException("同名登录任务已存在，但不属于 Codex 代理管理器；没有覆盖该任务。");

        var sourceDirectory = Path.GetFullPath(AppContext.BaseDirectory);
        var bundleFiles = GetBundleFiles(sourceDirectory);
        var installRoot = GetInstallRoot();
        Directory.CreateDirectory(installRoot);
        var fingerprint = ComputeBundleFingerprint(bundleFiles);
        var managerVersion = typeof(ProxyEngineService).Assembly.GetName().Version?.ToString() ?? "Unknown";
        var versionDirectory = Path.Combine(installRoot, "v" + managerVersion + "-" + fingerprint[..12]);

        if (!Directory.Exists(versionDirectory))
        {
            Directory.CreateDirectory(versionDirectory);
            SetProtectedAcl(versionDirectory);
            foreach (var (relativePath, sourcePath) in bundleFiles)
            {
                var destination = Path.Combine(versionDirectory, relativePath);
                Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                File.Copy(sourcePath, destination, overwrite: false);
                if (!string.Equals(ComputeFileHash(sourcePath), ComputeFileHash(destination), StringComparison.OrdinalIgnoreCase))
                    throw new IOException("Guardian 受保护安装副本校验失败：" + relativePath);
            }
        }
        else
        {
            VerifyExistingInstall(versionDirectory, bundleFiles);
        }

        var guardianPath = Path.Combine(versionDirectory, "CodexProxyGuardian.exe");
        var taskXmlPath = Path.Combine(GetRequestDirectory(), Guid.NewGuid().ToString("N") + ".task.xml");
        var oldTaskXmlPath = taskXmlPath + ".previous.xml";
        var previousRetired = false;
        try
        {
            if (existingTask.ExitCode == 0)
            {
                var oldVerification = VerifyRegisteredTaskXml(existingTask.StandardOutput, userSid);
                if (!oldVerification.Enabled)
                    throw new InvalidOperationException("旧登录任务未通过完整身份核验，拒绝升级：" + oldVerification.Detail);
                WriteTextCreateNew(oldTaskXmlPath, existingTask.StandardOutput, new UnicodeEncoding(false, true));
                var disabled = RunSchtasks(["/Change", "/TN", TaskName, "/DISABLE"], allowFailure: true);
                if (disabled.ExitCode != 0) throw new InvalidOperationException("未能暂停本产品旧任务，拒绝后台交接。");
            }
            GuardianLifecycle.RetirePrevious(guardianPath);
            previousRetired = true;
            WriteTextCreateNew(taskXmlPath, BuildTaskXml(userSid, guardianPath), new UnicodeEncoding(bigEndian: false, byteOrderMark: true));
            var result = RunSchtasks(["/Create", "/TN", TaskName, "/XML", taskXmlPath, "/F"], allowFailure: false);
            if (result.ExitCode != 0)
                throw new InvalidOperationException("任务计划程序拒绝注册 Guardian 登录任务：" + SummarizeProcessError(result));
            var verification = ReadRegisteredTaskVerification();
            if (!verification.Enabled)
                throw new InvalidOperationException("Guardian 登录任务注册后未通过只读核验：" + verification.Detail);
            if (!GuardianLifecycle.IsCurrentRunning(guardianPath)
                && !RequestImmediateRun(arguments => RunSchtasks(arguments, allowFailure: true).ExitCode, registrationVerified: true))
                throw new InvalidOperationException("新版后台任务已注册，但本次启动请求失败。");
            var started = Stopwatch.StartNew();
            while (started.Elapsed < TimeSpan.FromSeconds(30))
            {
                if (GuardianLifecycle.IsCurrentRunning(guardianPath)) return null;
                Thread.Sleep(250);
            }
            throw new InvalidOperationException("没有确认新版后台进程接替成功。");
        }
        catch
        {
            // The forwarding service/configuration is never changed by this control-plane upgrade.
            // Restore the previous task if installation/start failed; restore its controller only if we retired it.
            if (File.Exists(oldTaskXmlPath))
            {
                var restored = RunSchtasks(["/Create", "/TN", TaskName, "/XML", oldTaskXmlPath, "/F"], allowFailure: true);
                if (restored.ExitCode != 0)
                    throw new InvalidOperationException("后台交接失败，旧任务恢复也失败；转发服务未被改动，请导出诊断。");
                if (previousRetired) _ = RunSchtasks(["/Run", "/TN", TaskName], allowFailure: true);
            }
            throw;
        }
        finally
        {
            TryDelete(taskXmlPath);
            TryDelete(oldTaskXmlPath);
        }
    }

    internal static bool RequestImmediateRun(Func<IReadOnlyList<string>, int> run, bool registrationVerified)
    {
        if (!registrationVerified) return false;
        return run(["/Run", "/TN", TaskName]) == 0;
    }

    private static void UnregisterTask()
    {
        var query = RunSchtasks(["/Query", "/TN", TaskName, "/XML"], allowFailure: true);
        if (query.ExitCode != 0)
            return;
        if (!IsOwnedTaskXml(query.StandardOutput))
            throw new InvalidOperationException("同名登录任务不属于 Codex 代理管理器；拒绝删除。");

        var result = RunSchtasks(["/Delete", "/TN", TaskName, "/F"], allowFailure: true);
        if (result.ExitCode != 0)
            throw new InvalidOperationException("无法移除 Guardian 登录任务：" + SummarizeProcessError(result));
    }

    private static List<(string RelativePath, string SourcePath)> GetBundleFiles(string sourceDirectory, string? managerDll = null)
    {
        sourceDirectory = Path.GetFullPath(sourceDirectory);
        var relativePaths = new List<string>
        {
            "CodexProxyGuardian.exe",
            "CodexProxyGuardian.dll",
            "CodexProxyGuardian.deps.json",
            "CodexProxyGuardian.runtimeconfig.json",
            managerDll ?? (typeof(ProxyEngineService).Assembly.GetName().Name ?? "CodexProxyManager") + ".dll"
        };
        relativePaths.AddRange(EnginePayloadRelativeFiles);

        var files = new List<(string RelativePath, string SourcePath)>();
        foreach (var relativePath in relativePaths.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var sourcePath = Path.GetFullPath(Path.Combine(sourceDirectory, relativePath));
            if (!sourcePath.StartsWith(sourceDirectory.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                || !File.Exists(sourcePath)
                || (File.GetAttributes(sourcePath) & FileAttributes.ReparsePoint) != 0)
                throw new FileNotFoundException("候选目录缺少受限安装所需文件：" + relativePath, sourcePath);
            files.Add((relativePath, sourcePath));
        }

        return files;
    }

    internal static void VerifyInstalledBundle(string directory)
    {
        var managerFiles = Directory.GetFiles(directory, "Codex代理管理器_v*.dll", SearchOption.TopDirectoryOnly);
        if (managerFiles.Length != 1) throw new InvalidDataException("后台安装副本缺少唯一的管理器组件。");
        var version = System.Reflection.AssemblyName.GetAssemblyName(managerFiles[0]).Version?.ToString()
            ?? throw new InvalidDataException("后台安装版本无效。");
        var files = GetBundleFiles(directory, Path.GetFileName(managerFiles[0]));
        foreach (var file in files)
        {
            for (var cursor = Path.GetDirectoryName(file.SourcePath); cursor is not null; cursor = Path.GetDirectoryName(cursor))
                if ((File.GetAttributes(cursor) & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidDataException("后台安装副本包含重解析目录。");
        }
        var fingerprint = ComputeBundleFingerprint(files);
        if (!string.Equals(Path.GetFileName(directory), "v" + version + "-" + fingerprint[..12], StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("旧后台安装副本指纹不匹配，拒绝结束未知进程。");
    }

    private static string ComputeBundleFingerprint(IEnumerable<(string RelativePath, string SourcePath)> files)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var (relativePath, sourcePath) in files.OrderBy(item => item.RelativePath, StringComparer.OrdinalIgnoreCase))
        {
            hash.AppendData(Encoding.UTF8.GetBytes(relativePath.ToLowerInvariant() + "\0"));
            hash.AppendData(SHA256.HashData(File.ReadAllBytes(sourcePath)));
        }

        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private static void VerifyExistingInstall(string installDirectory, IEnumerable<(string RelativePath, string SourcePath)> files)
    {
        foreach (var (relativePath, sourcePath) in files)
        {
            var destination = Path.Combine(installDirectory, relativePath);
            if (!File.Exists(destination)
                || (File.GetAttributes(destination) & FileAttributes.ReparsePoint) != 0
                || !string.Equals(ComputeFileHash(sourcePath), ComputeFileHash(destination), StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("已有 Guardian 安装副本与当前候选不一致；没有覆盖该版本：" + relativePath);
        }
    }

    private static void SetProtectedAcl(string directory)
    {
        var result = RunIcacls(directory,
        [
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
            "*S-1-5-32-545:(OI)(CI)RX"
        ]);
        if (result.ExitCode != 0)
            throw new InvalidOperationException("无法设置 Program Files Guardian 安装目录权限：" + SummarizeProcessError(result));
    }

    private static ProcessResult RunSchtasks(IReadOnlyList<string> arguments, bool allowFailure)
    {
        var executable = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "schtasks.exe");
        var result = RunProcess(executable, arguments, TimeSpan.FromSeconds(20));
        if (!allowFailure && result.ExitCode != 0)
            return result;
        return result;
    }

    private static bool IsOwnedTaskXml(string xml)
    {
        try
        {
            var document = XDocument.Parse(xml);
            var ns = document.Root?.Name.Namespace ?? XNamespace.None;
            var taskUri = document.Root?.Descendants(ns + "RegistrationInfo").Elements(ns + "URI").FirstOrDefault()?.Value;
            return string.Equals(taskUri, TaskUri, StringComparison.Ordinal);
        }
        catch (System.Xml.XmlException)
        {
            return false;
        }
    }

    private static ProcessResult RunIcacls(string directory, IReadOnlyList<string> permissions)
    {
        var arguments = new List<string> { directory };
        arguments.AddRange(permissions);
        var executable = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "icacls.exe");
        return RunProcess(executable, arguments, TimeSpan.FromSeconds(20));
    }

    private static ProcessResult RunProcess(string executable, IReadOnlyList<string> arguments, TimeSpan timeout)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = executable,
                WorkingDirectory = Environment.SystemDirectory,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            }
        };
        foreach (var argument in arguments)
            process.StartInfo.ArgumentList.Add(argument);
        if (!process.Start())
            throw new InvalidOperationException(Path.GetFileName(executable) + " 未能启动。");

        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit((int)timeout.TotalMilliseconds))
        {
            try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            throw new TimeoutException(Path.GetFileName(executable) + " 超时。");
        }

        return new ProcessResult(process.ExitCode, stdout.GetAwaiter().GetResult(), stderr.GetAwaiter().GetResult());
    }

    private static Process StartElevatedHelper(string requestPath)
    {
        var processPath = Environment.ProcessPath ?? throw new InvalidOperationException("无法确定管理器启动路径。");
        var arguments = new List<string>();
        if (string.Equals(Path.GetFileNameWithoutExtension(processPath), "dotnet", StringComparison.OrdinalIgnoreCase))
        {
            var assemblyName = System.Reflection.Assembly.GetEntryAssembly()?.GetName().Name;
            if (!string.IsNullOrWhiteSpace(assemblyName))
                arguments.Add(Path.Combine(AppContext.BaseDirectory, assemblyName + ".dll"));
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
            Arguments = string.Join(' ', arguments.Select(QuoteArgument))
        };

        try
        {
            return Process.Start(startInfo) ?? throw new InvalidOperationException("无法启动 Guardian 安装权限助手。");
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            throw new InvalidOperationException("已取消 UAC；没有安装 Guardian 登录任务。");
        }
    }

    private static bool IsGuardianPathInInstallRoot(string? executablePath, string installRoot)
    {
        if (string.IsNullOrWhiteSpace(executablePath))
            return false;
        try
        {
            var path = Path.GetFullPath(executablePath);
            var root = Path.GetFullPath(installRoot).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            return path.StartsWith(root, StringComparison.OrdinalIgnoreCase)
                && string.Equals(Path.GetFileName(path), "CodexProxyGuardian.exe", StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or NotSupportedException)
        {
            return false;
        }
    }

    private static string GetRequestDirectory() => Path.GetFullPath(Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), AppDataFolder, RequestFolder));

    private static string ComputeFileHash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));

    private static string SummarizeProcessError(ProcessResult result)
    {
        var value = string.IsNullOrWhiteSpace(result.StandardError) ? result.StandardOutput : result.StandardError;
        return string.IsNullOrWhiteSpace(value) ? "退出码 " + result.ExitCode : value.Trim();
    }

    private static void WriteResponse(string path, GuardianTaskResponse response) =>
        WriteTextCreateNew(path, JsonSerializer.Serialize(response, JsonOptions), new UTF8Encoding(false));

    private static void WriteTextCreateNew(string path, string content, Encoding encoding)
    {
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        using var writer = new StreamWriter(stream, encoding);
        writer.Write(content);
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    private static string QuoteArgument(string value) => "\"" + value.Replace("\"", "\\\"", StringComparison.Ordinal) + "\"";

    private sealed record GuardianTaskRequest(string Action, string UserSid);
    private sealed record GuardianTaskResponse(bool Success, string Message, string? Warning = null);
    private sealed record ProcessResult(int ExitCode, string StandardOutput, string StandardError);
}

internal sealed record GuardianTaskVerification(bool Enabled, string Detail);
