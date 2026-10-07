using System.IO;
using System.Security.Cryptography;
using System.Text.Json;

namespace CodexProxyManager.Services;

internal sealed record LegacyConfigurationConsent(string ConfigSha256, string MarkerSha256);
internal sealed record LegacyConfigurationArchive(string InstallDirectory, string BackupDirectory, LegacyConfigurationConsent Consent);

/// <summary>Recognizes the old product format, never adopts it as ownership. Replacement requires UI consent.</summary>
internal static class LegacyConfigurationMigration
{
    private const string ConfigName = "app-config.json";
    private const string MarkerName = "codex-proxy-manager.json";
    private const string OwnerName = "CodexProxyManager.owner.json";

    internal static LegacyConfigurationConsent Inspect(string directory)
    {
        RequireOrdinaryDirectory(directory);
        if (File.Exists(Path.Combine(directory, OwnerName)))
            throw new InvalidOperationException("已有新版所有权标记，不能按旧版配置迁移。");
        var configBytes = ReadOrdinaryFile(Path.Combine(directory, ConfigName));
        var markerBytes = ReadOrdinaryFile(Path.Combine(directory, MarkerName));
        using var marker = JsonDocument.Parse(markerBytes);
        var m = marker.RootElement;
        RequireProperties(m, "Version", "Endpoint", "UpdatedAt");
        if (m.GetProperty("Version").GetString() != "2.6.1"
            || !DateTimeOffset.TryParse(m.GetProperty("UpdatedAt").GetString(), out _))
            throw new InvalidDataException("旧配置标记不是已识别的本产品格式；请保留文件并导出诊断。");
        var endpoint = m.GetProperty("Endpoint").GetString();
        using var config = JsonDocument.Parse(configBytes);
        var c = config.RootElement;
        RequireProperties(c, "logLevel", "bypassLan", "proxies", "excludes");
        var proxies = c.GetProperty("proxies");
        if (c.GetProperty("logLevel").GetString() != "Info"
            || c.GetProperty("bypassLan").ValueKind != JsonValueKind.False
            || proxies.ValueKind != JsonValueKind.Array || proxies.GetArrayLength() != 1
            || c.GetProperty("excludes").ValueKind != JsonValueKind.Array || c.GetProperty("excludes").GetArrayLength() != 0)
            throw new InvalidDataException("现有配置包含未识别设置，不会自动迁移或接管。");
        var p = proxies[0];
        RequireProperties(p, "appNames", "socks5ProxyEndpoint", "socks5Transport", "supportedProtocols", "supportedAddressFamilies");
        var apps = p.GetProperty("appNames");
        if (apps.ValueKind != JsonValueKind.Array || apps.GetArrayLength() != 1
            || !string.Equals(apps[0].GetString(), @"\WINDOWSAPPS\OPENAI.CODEX_", StringComparison.OrdinalIgnoreCase)
            || string.IsNullOrWhiteSpace(endpoint) || p.GetProperty("socks5ProxyEndpoint").GetString() != endpoint
            || p.GetProperty("socks5Transport").GetString() != "TCP"
            || !IsStringArray(p.GetProperty("supportedProtocols"), "TCP", "UDP")
            || !IsStringArray(p.GetProperty("supportedAddressFamilies"), "IPv4", "IPv6"))
            throw new InvalidDataException("现有规则不是已识别的旧版 Codex 单规则配置；拒绝扩大范围或覆盖其他规则。");
        return new LegacyConfigurationConsent(Hash(configBytes), Hash(markerBytes));
    }

    internal static LegacyConfigurationArchive Archive(string directory, LegacyConfigurationConsent consent)
    {
        var current = Inspect(directory);
        if (current != consent)
            throw new InvalidOperationException("确认后旧配置或标记已经变化，迁移取消；请重新检测。");
        var backupRoot = Path.Combine(directory, "CodexProxyManagerBackups");
        Directory.CreateDirectory(backupRoot);
        RequireOrdinaryDirectory(backupRoot);
        var backup = Path.Combine(backupRoot, "legacy-" + DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss-fff") + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(backup);
        RequireOrdinaryDirectory(backup);
        var archive = new LegacyConfigurationArchive(Path.GetFullPath(directory), backup, consent);
        // Verify both files immediately before their no-overwrite moves. No global network setting changes.
        if (Inspect(directory) != consent)
            throw new InvalidOperationException("备份前旧配置已经变化，迁移取消。");
        File.Move(Path.Combine(directory, ConfigName), Path.Combine(backup, ConfigName));
        try
        {
            File.Move(Path.Combine(directory, MarkerName), Path.Combine(backup, MarkerName));
            VerifyArchive(archive);
            File.WriteAllText(Path.Combine(backup, "migration.json"), JsonSerializer.Serialize(new
            {
                product = "CodexProxyManager", action = "ExplicitlyConfirmedLegacyReplacement",
                archivedAt = DateTimeOffset.UtcNow, consent.ConfigSha256, consent.MarkerSha256,
                note = "旧宽范围规则仅作恢复备份；新规则从当前已核验 MSIX 精确 EXE 重新生成。"
            }));
            return archive;
        }
        catch
        {
            // Preserve the archive even after rollback; never replace a concurrently created file.
            if (!File.Exists(Path.Combine(directory, ConfigName)))
                File.Copy(Path.Combine(backup, ConfigName), Path.Combine(directory, ConfigName), overwrite: false);
            if (!File.Exists(Path.Combine(directory, MarkerName)) && File.Exists(Path.Combine(backup, MarkerName)))
                File.Copy(Path.Combine(backup, MarkerName), Path.Combine(directory, MarkerName), overwrite: false);
            throw;
        }
    }

    internal static void RestoreIfEmpty(LegacyConfigurationArchive archive)
    {
        VerifyArchive(archive);
        RequireOrdinaryDirectory(archive.InstallDirectory);
        if (File.Exists(Path.Combine(archive.InstallDirectory, ConfigName))
            || File.Exists(Path.Combine(archive.InstallDirectory, MarkerName))
            || File.Exists(Path.Combine(archive.InstallDirectory, OwnerName)))
            throw new InvalidOperationException("安装目录已有新文件，拒绝用旧配置覆盖。旧文件仍完整保存在迁移备份目录。");
        File.Copy(Path.Combine(archive.BackupDirectory, ConfigName), Path.Combine(archive.InstallDirectory, ConfigName), overwrite: false);
        File.Copy(Path.Combine(archive.BackupDirectory, MarkerName), Path.Combine(archive.InstallDirectory, MarkerName), overwrite: false);
    }

    private static void VerifyArchive(LegacyConfigurationArchive archive)
    {
        RequireOrdinaryDirectory(archive.BackupDirectory);
        if (Hash(ReadOrdinaryFile(Path.Combine(archive.BackupDirectory, ConfigName))) != archive.Consent.ConfigSha256
            || Hash(ReadOrdinaryFile(Path.Combine(archive.BackupDirectory, MarkerName))) != archive.Consent.MarkerSha256)
            throw new InvalidDataException("旧配置备份指纹异常，拒绝恢复。");
    }

    private static void RequireProperties(JsonElement element, params string[] names)
    {
        if (element.ValueKind != JsonValueKind.Object
            || !element.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal)
                .SequenceEqual(names.Order(StringComparer.Ordinal), StringComparer.Ordinal))
            throw new InvalidDataException("旧配置存在未知或重复字段，拒绝自动迁移。");
    }

    private static bool IsStringArray(JsonElement element, params string[] values) =>
        element.ValueKind == JsonValueKind.Array
        && element.EnumerateArray().All(item => item.ValueKind == JsonValueKind.String)
        && element.EnumerateArray().Select(item => item.GetString()).SequenceEqual(values);

    private static byte[] ReadOrdinaryFile(string path)
    {
        var info = new FileInfo(path);
        if (!info.Exists || info.Length is < 1 or > 64 * 1024
            || (info.Attributes & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0)
            throw new InvalidDataException("旧配置文件缺失、过大或不是普通文件；拒绝自动迁移。");
        return File.ReadAllBytes(path);
    }

    private static void RequireOrdinaryDirectory(string path)
    {
        var info = new DirectoryInfo(path);
        if (!info.Exists || (info.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("配置或备份目录不是普通目录；拒绝迁移。");
    }

    private static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes));
}
