using System.Security.Cryptography;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace CodexProxyManager.Services;

internal sealed record ProxyScopePlan(
    IReadOnlyList<string> ExecutablePaths,
    IReadOnlyList<string> Warnings,
    string RuleDescription);

/// <summary>
/// Builds exact-path rules for approved MSIX executables and their verified deterministic runtime copies.
/// ProxiFyre implements substring matching, so this class rejects broad and shared executable names.
/// </summary>
internal static class ProxyScopePolicy
{
    private static readonly HashSet<string> SharedExecutableNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "python.exe", "pythonw.exe", "node.exe", "git.exe", "powershell.exe", "pwsh.exe",
        "cmd.exe", "wsl.exe", "svchost.exe", "rundll32.exe"
    };

    public static ProxyScopePlan CreatePlan(
        string installLocation,
        IEnumerable<string> manifestExecutablePaths,
        IEnumerable<string>? observedImagePaths = null)
    {
        var root = Path.GetFullPath(installLocation).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (string.IsNullOrWhiteSpace(root))
            throw new InvalidDataException("ChatGPT 安装目录为空，拒绝生成代理规则。");

        var paths = manifestExecutablePaths
            .Select(Path.GetFullPath)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (paths.Length == 0)
            throw new InvalidDataException("所选应用清单没有可用的执行文件，拒绝生成代理规则。");

        foreach (var path in paths)
        {
            var relative = Path.GetRelativePath(root, path);
            if (Path.IsPathRooted(relative)
                || relative.Equals("..", StringComparison.Ordinal)
                || relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal)
                || relative.StartsWith(".." + Path.AltDirectorySeparatorChar, StringComparison.Ordinal))
                RelocatedBackendDiscovery.VerifyExpectedRulePath(root, path);

            if (!string.Equals(Path.GetExtension(path), ".exe", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException($"应用清单包含非 EXE 执行文件：{Path.GetFileName(path)}");

            if (SharedExecutableNames.Contains(Path.GetFileName(path)))
                throw new InvalidDataException($"拒绝把共享系统工具加入代理规则：{Path.GetFileName(path)}");
        }

        var collisions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var imagePath in observedImagePaths ?? [])
        {
            if (string.IsNullOrWhiteSpace(imagePath)) continue;
            var fullImagePath = Path.GetFullPath(imagePath);
            foreach (var rulePath in paths)
            {
                // Upstream v2.6.1 path rules are substring matches, not path equality.
                if (fullImagePath.Contains(rulePath, StringComparison.OrdinalIgnoreCase)
                    && !string.Equals(fullImagePath, rulePath, StringComparison.OrdinalIgnoreCase))
                    collisions.Add($"{Path.GetFileName(rulePath)} ↔ {Path.GetFileName(fullImagePath)}");
            }
        }

        var warnings = new List<string>
        {
            "ProxiFyre 按完整路径子串匹配，不提供原生 PID、进程树或 MSIX 身份隔离；同一可执行路径的所有实例都会匹配。",
            "范围只包含已审核的 MSIX 网络组件和由同一包资源指纹确定的后台缓存具体 EXE；外置 CLI 与共享工具不自动纳入。",
            "路径规则修改需要重启 ProxiFyreService 才会加载。"
        };
        if (collisions.Count > 0)
            throw new InvalidDataException("发现可能被路径子串误匹配的进程：" + string.Join("、", collisions));

        return new ProxyScopePlan(paths, warnings, $"{paths.Length} 个已核验客户端及后台 EXE 的完整路径子串规则");
    }
}

internal static class ProxiFyreConfigurationBuilder
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public static string Create(ProxyEndpoint endpoint, ProxyScopePlan plan)
    {
        if (plan.ExecutablePaths.Count == 0 || plan.ExecutablePaths.Any(string.IsNullOrWhiteSpace))
            throw new InvalidDataException("代理规则不能为空或缺少执行文件。");

        var config = new EngineConfiguration(
            LogLevel: "Info",
            BypassLan: true,
            Proxies:
            [
                new EngineProxyRule(
                    AppNames: plan.ExecutablePaths,
                    Socks5ProxyEndpoint: endpoint.Display,
                    Username: string.Empty,
                    Password: string.Empty,
                    Socks5Transport: "TCP",
                    SupportedProtocols: ["TCP", "UDP"],
                    SupportedAddressFamilies: ["IPv4", "IPv6"])
            ],
            Excludes: []);

        var json = JsonSerializer.Serialize(config, JsonOptions);
        Validate(json, plan.ExecutablePaths);
        return json;
    }

    public static string CreateOrUpdate(ProxyEndpoint endpoint, ProxyScopePlan plan, string? existingJson)
    {
        if (string.IsNullOrWhiteSpace(existingJson))
            return Create(endpoint, plan);

        if (plan.ExecutablePaths.Count == 0 || plan.ExecutablePaths.Any(string.IsNullOrWhiteSpace))
            throw new InvalidDataException("代理规则不能为空或缺少执行文件。");

        var root = JsonNode.Parse(existingJson) as JsonObject
            ?? throw new InvalidDataException("已有 ProxiFyre 配置不是 JSON 对象，拒绝重写。");
        var existingRules = root["proxies"] as JsonArray;
        if (existingRules is not null && existingRules.Count > 1)
            throw new InvalidDataException("已拥有的 ProxiFyre 配置包含多条代理规则；为避免改变其他规则，本次拒绝自动合并。");
        if (root.ContainsKey("proxies") && existingRules is null)
            throw new InvalidDataException("已有 ProxiFyre 配置的 proxies 不是数组，拒绝重写。");

        var rule = existingRules is { Count: 1 }
            ? existingRules[0]?.DeepClone() as JsonObject
                ?? throw new InvalidDataException("已有 ProxiFyre 代理规则不是 JSON 对象，拒绝重写。")
            : new JsonObject();

        rule["appNames"] = JsonSerializer.SerializeToNode(plan.ExecutablePaths);
        rule["socks5ProxyEndpoint"] = endpoint.Display;
        rule["username"] = string.Empty;
        rule["password"] = string.Empty;
        rule["socks5Transport"] = "TCP";
        rule["supportedProtocols"] = JsonSerializer.SerializeToNode(new[] { "TCP", "UDP" });
        rule["supportedAddressFamilies"] = JsonSerializer.SerializeToNode(new[] { "IPv4", "IPv6" });

        root["logLevel"] ??= "Info";
        root["bypassLan"] ??= true;
        root["excludes"] ??= new JsonArray();
        root["proxies"] = new JsonArray(rule);

        var json = root.ToJsonString(JsonOptions);
        Validate(json, plan.ExecutablePaths, endpoint);
        return json;
    }

    public static void Validate(string json, IReadOnlyList<string> expectedPaths, ProxyEndpoint? expectedEndpoint = null)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object
            || !root.TryGetProperty("logLevel", out var logLevel) || logLevel.ValueKind != JsonValueKind.String
            || !root.TryGetProperty("bypassLan", out var bypassLan) || bypassLan.ValueKind is not (JsonValueKind.True or JsonValueKind.False)
            || !root.TryGetProperty("excludes", out var excludes) || excludes.ValueKind != JsonValueKind.Array
            || !root.TryGetProperty("proxies", out var proxies) || proxies.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("配置缺少 ProxiFyre v2.6.1 所需结构。");

        RejectUnsupportedIdentityFields(root);
        if (proxies.GetArrayLength() != 1)
            throw new InvalidDataException("Codex 专用配置必须包含且只包含一条代理规则。");
        var rule = proxies[0];
        if (rule.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("Codex 代理规则不是 JSON 对象。");
        var actualPaths = rule.GetProperty("appNames").EnumerateArray().Select(value => value.GetString() ?? string.Empty).ToArray();
        if (!HaveSameExecutablePaths(actualPaths, expectedPaths))
            throw new InvalidDataException("配置中的应用规则与本次审核的路径范围不一致。");

        if (!rule.TryGetProperty("socks5ProxyEndpoint", out var configuredEndpoint)
            || configuredEndpoint.ValueKind != JsonValueKind.String
            || (expectedEndpoint is not null && !string.Equals(configuredEndpoint.GetString(), expectedEndpoint.Display, StringComparison.OrdinalIgnoreCase)))
            throw new InvalidDataException("配置中的 SOCKS5 endpoint 与本次验证值不一致。");
        if (!rule.TryGetProperty("username", out var username) || username.GetString() != string.Empty
            || !rule.TryGetProperty("password", out var password) || password.GetString() != string.Empty)
            throw new InvalidDataException("本配置不接受未审核的 SOCKS5 认证凭据。");
        if (!rule.TryGetProperty("socks5Transport", out var transport) || transport.GetString() != "TCP"
            || !HasExactStrings(rule, "supportedProtocols", ["TCP", "UDP"])
            || !HasExactStrings(rule, "supportedAddressFamilies", ["IPv4", "IPv6"]))
            throw new InvalidDataException("配置的传输协议或地址族与已核验能力不一致。");
    }

    internal static bool HaveSameExecutablePaths(IEnumerable<string?> actual, IEnumerable<string?> expected)
    {
        var actualPaths = actual.ToArray();
        var expectedPaths = expected.ToArray();
        // All entries in this single proxy rule have the same endpoint/protocols; order is not identity.
        // Reject duplicates as well as empty, missing and extra paths, rather than collapsing them into a set.
        if (actualPaths.Length == 0 || actualPaths.Length != expectedPaths.Length
            || actualPaths.Any(string.IsNullOrWhiteSpace) || expectedPaths.Any(string.IsNullOrWhiteSpace)
            || actualPaths.Distinct(StringComparer.OrdinalIgnoreCase).Count() != actualPaths.Length
            || expectedPaths.Distinct(StringComparer.OrdinalIgnoreCase).Count() != expectedPaths.Length)
            return false;
        return actualPaths.OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
            .SequenceEqual(expectedPaths.OrderBy(path => path, StringComparer.OrdinalIgnoreCase), StringComparer.OrdinalIgnoreCase);
    }

    private static bool HasExactStrings(JsonElement rule, string propertyName, IReadOnlyList<string> expected) =>
        rule.TryGetProperty(propertyName, out var value)
        && value.ValueKind == JsonValueKind.Array
        && value.EnumerateArray().Select(item => item.GetString()).SequenceEqual(expected, StringComparer.Ordinal);

    private static readonly HashSet<string> UnsupportedIdentityFields = new(StringComparer.OrdinalIgnoreCase)
    {
        "pid", "includeChildren", "inheritChildren", "packageFamilyName", "remoteDns"
    };

    private static void RejectUnsupportedIdentityFields(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in element.EnumerateObject())
            {
                if (UnsupportedIdentityFields.Contains(property.Name))
                    throw new InvalidDataException($"配置包含 ProxiFyre v2.6.1 不支持的身份/远端 DNS 字段：{property.Name}。");
                RejectUnsupportedIdentityFields(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray()) RejectUnsupportedIdentityFields(item);
        }
    }

    private sealed record EngineConfiguration(string LogLevel, bool BypassLan, IReadOnlyList<EngineProxyRule> Proxies, IReadOnlyList<string> Excludes);
    private sealed record EngineProxyRule(
        IReadOnlyList<string> AppNames,
        string Socks5ProxyEndpoint,
        string Username,
        string Password,
        string Socks5Transport,
        IReadOnlyList<string> SupportedProtocols,
        IReadOnlyList<string> SupportedAddressFamilies);
}

internal sealed record ManagedConfigSnapshot(string? ConfigHash, string? OwnerHash, string? BackupDirectory);

internal sealed record EngineRuleVerification(string Status, string Detail);

/// <summary>Atomically writes a managed config, preserving a recoverable prior state and refusing drift.</summary>
internal static class ManagedConfigurationStore
{
    private const string ProductName = "CodexProxyManager";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public static void ValidateOwnership(string configPath, string ownerPath)
    {
        var hasConfig = File.Exists(configPath);
        var hasOwner = File.Exists(ownerPath);
        if (hasConfig != hasOwner)
            throw new InvalidOperationException("ProxiFyre 配置和所有权标记状态不一致，拒绝覆盖。");
        if (!hasConfig) return;

        try
        {
            using var owner = JsonDocument.Parse(File.ReadAllText(ownerPath));
            if (!string.Equals(owner.RootElement.GetProperty("product").GetString(), ProductName, StringComparison.Ordinal)
                || !string.Equals(owner.RootElement.GetProperty("configSha256").GetString(), ComputeHash(configPath), StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("ProxiFyre 配置指纹已变化或不是本管理器创建；拒绝覆盖。");
        }
        catch (Exception ex) when (ex is IOException or JsonException or KeyNotFoundException or InvalidOperationException)
        {
            if (ex is InvalidOperationException invalid && invalid.Message.StartsWith("ProxiFyre 配置指纹", StringComparison.Ordinal)) throw;
            throw new InvalidOperationException("无法确认现有 ProxiFyre 配置的所有权，拒绝修改。", ex);
        }
    }

    public static ManagedConfigSnapshot Apply(string configPath, string ownerPath, string contents) =>
        Apply(configPath, ownerPath, _ => contents);

    public static ManagedConfigSnapshot Apply(string configPath, string ownerPath, Func<string?, string> createContents)
    {
        ArgumentNullException.ThrowIfNull(createContents);
        configPath = Path.GetFullPath(configPath);
        ownerPath = Path.GetFullPath(ownerPath);
        var directory = Path.GetDirectoryName(configPath) ?? throw new InvalidOperationException("配置目录无效。");
        if (!string.Equals(directory, Path.GetDirectoryName(ownerPath), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("配置与所有权标记必须位于同一受保护目录。");

        var oldConfigExists = File.Exists(configPath);
        var oldOwnerExists = File.Exists(ownerPath);
        var beforeConfigHash = oldConfigExists ? ComputeHash(configPath) : null;
        var beforeOwnerHash = oldOwnerExists ? ComputeHash(ownerPath) : null;
        ValidateOwnership(configPath, ownerPath);

        var oldContents = oldConfigExists ? File.ReadAllText(configPath) : null;
        if (oldConfigExists && !string.Equals(ComputeHash(configPath), beforeConfigHash, StringComparison.OrdinalIgnoreCase))
            throw new IOException("读取现有配置时检测到文件变化；本次应用已取消。");
        var contents = createContents(oldContents);
        if (contents is null)
            throw new InvalidDataException("配置生成器没有返回内容。");

        if (oldConfigExists)
        {
            using var owner = JsonDocument.Parse(File.ReadAllText(ownerPath));
            if (!string.Equals(owner.RootElement.GetProperty("product").GetString(), ProductName, StringComparison.Ordinal)
                || !string.Equals(owner.RootElement.GetProperty("configSha256").GetString(), beforeConfigHash, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("ProxiFyre 配置指纹已变化或不是本管理器创建；拒绝覆盖。");
        }

        var backupDirectory = oldConfigExists
            ? Path.Combine(directory, "CodexProxyManagerBackups", DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss-fff") + "-" + Guid.NewGuid().ToString("N"))
            : null;
        if (backupDirectory is not null)
        {
            Directory.CreateDirectory(backupDirectory);
            var backupConfig = Path.Combine(backupDirectory, "app-config.json");
            var backupOwner = Path.Combine(backupDirectory, "owner.json");
            File.Copy(configPath, backupConfig);
            File.Copy(ownerPath, backupOwner);
            if (!string.Equals(ComputeHash(backupConfig), beforeConfigHash, StringComparison.OrdinalIgnoreCase)
                || !string.Equals(ComputeHash(backupOwner), beforeOwnerHash, StringComparison.OrdinalIgnoreCase))
                throw new IOException("配置备份 SHA-256 与应用前文件不一致；本次没有修改引擎配置。");
        }

        var newConfigHash = ComputeHash(Encoding.UTF8.GetBytes(contents));
        var ownerContents = CreateOwnerContents(newConfigHash, backupDirectory, null);

        try
        {
            if (File.Exists(configPath) != oldConfigExists
                || File.Exists(ownerPath) != oldOwnerExists
                || (oldConfigExists && !string.Equals(ComputeHash(configPath), beforeConfigHash, StringComparison.OrdinalIgnoreCase))
                || (oldOwnerExists && !string.Equals(ComputeHash(ownerPath), beforeOwnerHash, StringComparison.OrdinalIgnoreCase)))
                throw new IOException("保存期间检测到配置被其他程序修改；本次应用已取消。");

            AtomicWrite(configPath, contents);
            AtomicWrite(ownerPath, ownerContents);
            return new ManagedConfigSnapshot(newConfigHash, ComputeHash(ownerPath), backupDirectory);
        }
        catch
        {
            // Restore only if the current bytes still match this transaction's candidate.
            if (File.Exists(configPath) && string.Equals(ComputeHash(configPath), newConfigHash, StringComparison.OrdinalIgnoreCase))
            {
                if (oldConfigExists && backupDirectory is not null)
                    AtomicWriteBytes(configPath, File.ReadAllBytes(Path.Combine(backupDirectory, "app-config.json")));
                else
                    File.Delete(configPath);
            }
            if (File.Exists(ownerPath))
            {
                if (oldOwnerExists && backupDirectory is not null
                    && string.Equals(ReadOwnerConfigHash(ownerPath), newConfigHash, StringComparison.OrdinalIgnoreCase))
                    AtomicWriteBytes(ownerPath, File.ReadAllBytes(Path.Combine(backupDirectory, "owner.json")));
                else if (!oldOwnerExists && string.Equals(ReadOwnerConfigHash(ownerPath), newConfigHash, StringComparison.OrdinalIgnoreCase))
                    File.Delete(ownerPath);
            }
            throw;
        }
    }

    public static void Rollback(string configPath, string ownerPath, ManagedConfigSnapshot snapshot)
    {
        if (snapshot.ConfigHash is null || snapshot.OwnerHash is null)
            throw new InvalidOperationException("回滚票据无效。");
        if (!File.Exists(configPath) || !File.Exists(ownerPath)
            || !string.Equals(ComputeHash(configPath), snapshot.ConfigHash, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(ComputeHash(ownerPath), snapshot.OwnerHash, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("配置已被外部修改；为保护他人更改，拒绝自动回滚。");

        if (snapshot.BackupDirectory is null)
        {
            File.Delete(configPath);
            File.Delete(ownerPath);
            return;
        }

        var backupConfig = Path.Combine(snapshot.BackupDirectory, "app-config.json");
        var backupOwner = Path.Combine(snapshot.BackupDirectory, "owner.json");
        if (!File.Exists(backupConfig) || !File.Exists(backupOwner))
            throw new FileNotFoundException("配置备份不完整，拒绝回滚。");
        AtomicWriteBytes(configPath, File.ReadAllBytes(backupConfig));
        AtomicWriteBytes(ownerPath, File.ReadAllBytes(backupOwner));
    }

    public static ManagedConfigSnapshot CaptureSnapshot(string configPath, string ownerPath)
    {
        ValidateOwnership(configPath, ownerPath);
        if (!File.Exists(configPath) || !File.Exists(ownerPath))
            throw new InvalidOperationException("无法为未配置的 ProxiFyre 服务创建核验快照。");
        using var owner = JsonDocument.Parse(File.ReadAllText(ownerPath));
        var backupDirectory = owner.RootElement.TryGetProperty("backupDirectory", out var backup)
            && backup.ValueKind == JsonValueKind.String
                ? backup.GetString()
                : null;
        return new ManagedConfigSnapshot(ComputeHash(configPath), ComputeHash(ownerPath), backupDirectory);
    }

    public static ManagedConfigSnapshot ClearEngineReadyEvidence(string configPath, string ownerPath, ManagedConfigSnapshot snapshot)
    {
        if (snapshot.ConfigHash is null || snapshot.OwnerHash is null
            || !File.Exists(configPath) || !File.Exists(ownerPath)
            || !string.Equals(ComputeHash(configPath), snapshot.ConfigHash, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(ComputeHash(ownerPath), snapshot.OwnerHash, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("启动服务前所有权或配置指纹已变化，拒绝清除核验状态。");
        ValidateOwnership(configPath, ownerPath);
        AtomicWrite(ownerPath, CreateOwnerContents(snapshot.ConfigHash, snapshot.BackupDirectory, null));
        return snapshot with { OwnerHash = ComputeHash(ownerPath) };
    }

    public static ManagedConfigSnapshot RecordEngineReady(
        string configPath,
        string ownerPath,
        ManagedConfigSnapshot snapshot,
        ProxyEndpoint endpoint,
        IReadOnlyList<string> rulePaths,
        DateTimeOffset verifiedAt)
    {
        if (snapshot.ConfigHash is null || snapshot.OwnerHash is null
            || !File.Exists(configPath) || !File.Exists(ownerPath)
            || !string.Equals(ComputeHash(configPath), snapshot.ConfigHash, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(ComputeHash(ownerPath), snapshot.OwnerHash, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("服务日志核验期间配置所有权或文件指纹发生变化，拒绝记录 Ready 证据。");

        ValidateOwnership(configPath, ownerPath);
        ProxiFyreConfigurationBuilder.Validate(File.ReadAllText(configPath), rulePaths, endpoint);
        var ownerContents = CreateOwnerContents(snapshot.ConfigHash, snapshot.BackupDirectory,
            new EngineReadyEvidence(endpoint.Display, rulePaths.ToArray(), verifiedAt));
        AtomicWrite(ownerPath, ownerContents);
        return snapshot with { OwnerHash = ComputeHash(ownerPath) };
    }

    public static EngineRuleVerification VerifyCurrentRules(
        string configPath,
        string ownerPath,
        ProxyEndpoint? endpoint,
        IReadOnlyList<string>? rulePaths)
    {
        if (endpoint is null || rulePaths is null || rulePaths.Count == 0)
            return new EngineRuleVerification("Unknown", "SOCKS5 endpoint 或当前 Codex 规则尚未发现。");
        if (!File.Exists(configPath) || !File.Exists(ownerPath))
            return new EngineRuleVerification("Fail", "ProxiFyre 配置或所有权标记缺失。");

        try
        {
            ValidateOwnership(configPath, ownerPath);
            ProxiFyreConfigurationBuilder.Validate(File.ReadAllText(configPath), rulePaths, endpoint);
            using var owner = JsonDocument.Parse(File.ReadAllText(ownerPath));
            if (!owner.RootElement.TryGetProperty("engineReadyEvidence", out var evidence)
                || evidence.ValueKind != JsonValueKind.Object
                || !evidence.TryGetProperty("endpoint", out var recordedEndpoint)
                || !string.Equals(recordedEndpoint.GetString(), endpoint.Display, StringComparison.OrdinalIgnoreCase)
                || !evidence.TryGetProperty("rulePaths", out var recordedPaths)
                || recordedPaths.ValueKind != JsonValueKind.Array
                || !ProxiFyreConfigurationBuilder.HaveSameExecutablePaths(
                    recordedPaths.EnumerateArray().Select(value => value.GetString()), rulePaths)
                || !evidence.TryGetProperty("verifiedAtUtc", out var verifiedAt)
                || !DateTimeOffset.TryParse(verifiedAt.GetString(), out var timestamp)
                || timestamp > DateTimeOffset.UtcNow.AddMinutes(1))
                return new EngineRuleVerification("Unknown", "当前配置有效，但没有对应的服务启动日志核验记录。");

            return new EngineRuleVerification("Pass", $"当前 endpoint 与 {rulePaths.Count} 条精确路径匹配；引擎启动日志核验于 {timestamp:O} 完成。");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or InvalidDataException or JsonException or KeyNotFoundException or ArgumentException)
        {
            return new EngineRuleVerification("Fail", "当前配置/规则核验失败（" + ex.GetType().Name + "）。");
        }
    }

    public static string ComputeHash(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static string ComputeHash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes));

    private static string CreateOwnerContents(string configHash, string? backupDirectory, EngineReadyEvidence? evidence) =>
        JsonSerializer.Serialize(new
        {
            product = ProductName,
            schemaVersion = 2,
            engineVersion = "2.6.1",
            configSha256 = configHash,
            backupDirectory,
            engineReadyEvidence = evidence
        }, JsonOptions);

    private sealed record EngineReadyEvidence(string Endpoint, string[] RulePaths, DateTimeOffset VerifiedAtUtc);
    private static string? ReadOwnerConfigHash(string path)
    {
        try { using var json = JsonDocument.Parse(File.ReadAllText(path)); return json.RootElement.GetProperty("configSha256").GetString(); }
        catch (Exception ex) when (ex is IOException or JsonException or KeyNotFoundException) { return null; }
    }

    private static void AtomicWrite(string path, string contents)
        => AtomicWriteBytes(path, new UTF8Encoding(false).GetBytes(contents));

    private static void AtomicWriteBytes(string path, byte[] contents)
    {
        var temporaryPath = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                stream.Write(contents, 0, contents.Length);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporaryPath, path, overwrite: true);
        }
        finally { try { File.Delete(temporaryPath); } catch { } }
    }
}
