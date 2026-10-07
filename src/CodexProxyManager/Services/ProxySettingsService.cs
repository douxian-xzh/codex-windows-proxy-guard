using System.IO;
using System.Net;
using System.Text.Json;
using Microsoft.Win32;

namespace CodexProxyManager.Services;

public sealed record ProxyEndpoint(string Host, int Port)
{
    public string Display => IPAddress.TryParse(Host, out var address)
        && address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? $"[{Host}]:{Port}"
            : $"{Host}:{Port}";

    public bool Matches(IPAddress address, int port)
    {
        if (port != Port || !IPAddress.TryParse(Host, out var configuredAddress))
        {
            return false;
        }

        return configuredAddress.Equals(address)
            || (configuredAddress.IsIPv4MappedToIPv6 && configuredAddress.MapToIPv4().Equals(address))
            || (address.IsIPv4MappedToIPv6 && address.MapToIPv4().Equals(configuredAddress));
    }

    public static bool TryCreate(string host, string portText, out ProxyEndpoint? endpoint, out string error)
    {
        endpoint = null;
        error = string.Empty;
        host = host.Trim();
        if (string.IsNullOrWhiteSpace(host))
        {
            error = "请输入代理 IP 或主机名。";
            return false;
        }

        if (host.Contains('/') || host.Contains('@') || host.Any(char.IsWhiteSpace))
        {
            error = "代理地址只填写 IP/主机名，不包含协议、路径或认证信息。";
            return false;
        }

        if (!IPAddress.TryParse(host, out _) && Uri.CheckHostName(host) == UriHostNameType.Unknown)
        {
            error = "代理 IP 或主机名格式无效。";
            return false;
        }

        if (!int.TryParse(portText.Trim(), out var port) || port is < 1 or > 65535)
        {
            error = "端口必须是 1 到 65535 之间的整数。";
            return false;
        }

        endpoint = new ProxyEndpoint(host, port);
        return true;
    }

}

public sealed record SystemProxyInfo(
    bool Enabled,
    ProxyEndpoint? Endpoint,
    bool HasPac,
    bool AutoDetect,
    int BypassCount,
    bool IncludesLocal,
    bool HasCredentials,
    string ModeDescription);

public sealed record AppSettings(
    bool FollowSystemProxy,
    string? CustomHost,
    int? CustomPort,
    bool RunAtLogon,
    string? SelectedPackageFullName = null);

public sealed class ProxySettingsService
{
    private const string InternetSettingsPath = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    private const string SettingsDirectoryName = "CodexProxyManagerPywBranch";
    private const string SettingsFileName = "settings.json";

    private readonly string _settingsPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        SettingsDirectoryName,
        SettingsFileName);

    public SystemProxyInfo ReadSystemProxy()
    {
        using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsPath);
        if (key is null)
        {
            return new SystemProxyInfo(false, null, false, false, 0, false, false, "无法读取当前用户代理设置");
        }

        var enabled = ReadInt(key, "ProxyEnable") != 0;
        var server = key.GetValue("ProxyServer") as string ?? string.Empty;
        var bypass = (key.GetValue("ProxyOverride") as string ?? string.Empty)
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var hasPac = !string.IsNullOrWhiteSpace(key.GetValue("AutoConfigURL") as string);
        var autoDetect = ReadInt(key, "AutoDetect") != 0;
        var endpoint = enabled ? ParseEndpoint(server) : null;
        var credentials = server.Contains('@');

        var mode = !enabled && (hasPac || autoDetect)
            ? "自动代理配置（V1 需手动输入固定端点）"
            : enabled && endpoint is not null
                ? "固定代理"
                : enabled
                    ? "代理格式暂不支持"
                    : "未启用固定代理";

        return new SystemProxyInfo(
            enabled,
            endpoint,
            hasPac,
            autoDetect,
            bypass.Length,
            bypass.Any(value => string.Equals(value, "<local>", StringComparison.OrdinalIgnoreCase)),
            credentials,
            mode);
    }

    public AppSettings? Load()
    {
        try
        {
            if (!File.Exists(_settingsPath))
            {
                return null;
            }

            return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(_settingsPath));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }

    public void Save(AppSettings settings)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_settingsPath)!);
        var json = JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(_settingsPath, json);
    }

    private static int ReadInt(RegistryKey key, string name)
    {
        try
        {
            return Convert.ToInt32(key.GetValue(name) ?? 0);
        }
        catch (FormatException)
        {
            return 0;
        }
        catch (InvalidCastException)
        {
            return 0;
        }
    }

    private static ProxyEndpoint? ParseEndpoint(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var entries = value.Contains('=')
            ? value.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            : [value.Trim()];

        var parsed = new Dictionary<string, ProxyEndpoint>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries)
        {
            var separator = entry.IndexOf('=');
            var scheme = separator >= 0 ? entry[..separator].Trim() : "default";
            var rawAddress = separator >= 0 ? entry[(separator + 1)..].Trim() : entry.Trim();
            var endpoint = ParseAddress(rawAddress);
            if (endpoint is not null)
            {
                parsed[scheme] = endpoint;
            }
        }

        return parsed.GetValueOrDefault("https")
            ?? parsed.GetValueOrDefault("http")
            ?? parsed.GetValueOrDefault("default")
            ?? parsed.Values.FirstOrDefault();
    }

    private static ProxyEndpoint? ParseAddress(string value)
    {
        if (Uri.TryCreate(value, UriKind.Absolute, out var absolute)
            && string.Equals(absolute.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
        {
            return absolute.Port > 0 ? new ProxyEndpoint(absolute.Host, absolute.Port) : null;
        }

        var address = value.Trim().TrimEnd('/');
        if (address.StartsWith("[", StringComparison.Ordinal))
        {
            var end = address.IndexOf(']');
            if (end > 0 && end + 2 < address.Length
                && IPAddress.TryParse(address[1..end], out _)
                && int.TryParse(address[(end + 2)..], out var ipv6Port)
                && ipv6Port is > 0 and <= 65535)
            {
                return new ProxyEndpoint(address[1..end], ipv6Port);
            }

            return null;
        }

        var separator = address.LastIndexOf(':');
        if (separator <= 0 || !int.TryParse(address[(separator + 1)..], out var port) || port is < 1 or > 65535)
        {
            return null;
        }

        var host = address[..separator];
        return IPAddress.TryParse(host, out _) || Uri.CheckHostName(host) != UriHostNameType.Unknown
            ? new ProxyEndpoint(host, port)
            : null;
    }
}

public sealed class SettingsStore
{
    private readonly ProxySettingsService _proxySettings;

    public SettingsStore(ProxySettingsService proxySettings) => _proxySettings = proxySettings;

    public AppSettings LoadOrInitialize()
    {
        var system = _proxySettings.ReadSystemProxy();
        var stored = _proxySettings.Load();
        if (stored is not null)
        {
            if (!stored.FollowSystemProxy)
            {
                return stored;
            }

            var current = stored with
            {
                CustomHost = system.Endpoint?.Host,
                CustomPort = system.Endpoint?.Port
            };
            _proxySettings.Save(current);
            return current;
        }

        return new AppSettings(
            FollowSystemProxy: true,
            CustomHost: system.Endpoint?.Host,
            CustomPort: system.Endpoint?.Port,
            RunAtLogon: StartupManager.IsEnabled());
    }

    public void Save(AppSettings settings) => _proxySettings.Save(settings);
}

public static class StartupManager
{
    public static bool IsEnabled() => GuardianTaskInstaller.IsEnabled();

    public static string? SetEnabled(bool enabled) => GuardianTaskInstaller.SetEnabled(enabled);

    public static void RemoveLegacyManagerRunEntry() => GuardianTaskInstaller.RemoveLegacyManagerRunEntry();
}
