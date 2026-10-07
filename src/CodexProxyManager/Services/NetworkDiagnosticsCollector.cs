using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace CodexProxyManager.Services;

internal sealed record NetworkInterfaceDiagnostic(
    string Name,
    string Type,
    string OperationalStatus,
    IReadOnlyList<string> Addresses,
    IReadOnlyList<string> DnsServers);

internal sealed record HostDnsDiagnostic(
    string Host,
    string Status,
    IReadOnlyList<string> Ipv4Addresses,
    IReadOnlyList<string> Ipv6Addresses,
    double DurationMs)
{
    public string Format() =>
        $"{Host}: A=[{(Ipv4Addresses.Count == 0 ? "无" : string.Join(", ", Ipv4Addresses))}] " +
        $"AAAA=[{(Ipv6Addresses.Count == 0 ? "无" : string.Join(", ", Ipv6Addresses))}] 状态={Status} ({DurationMs:F0} ms)";
}

internal sealed record NetworkDiagnosticsSnapshot(
    DateTimeOffset CapturedAt,
    bool NetworkAvailable,
    IReadOnlyList<string> SystemDnsServers,
    IReadOnlyList<NetworkInterfaceDiagnostic> Interfaces,
    IReadOnlyList<HostDnsDiagnostic> HostResolutions)
{
    public string Format()
    {
        var report = new StringBuilder();
        report.AppendLine($"快照时间：{CapturedAt.ToLocalTime():yyyy-MM-dd HH:mm:ss zzz}");
        report.AppendLine($"系统网络可用标记：{(NetworkAvailable ? "Yes" : "No")}");
        report.AppendLine($"活动网卡配置的 DNS 服务器：{(SystemDnsServers.Count == 0 ? "未读取到" : string.Join(", ", SystemDnsServers))}");
        report.AppendLine("网卡（名称、类型、状态、本机 IPv4/IPv6、DNS；不含 MAC 地址）：");
        if (Interfaces.Count == 0)
        {
            report.AppendLine("  未读取到网卡信息。");
        }
        else
        {
            foreach (var adapter in Interfaces)
            {
                report.AppendLine(
                    $"  {adapter.Name} · {adapter.Type} · {adapter.OperationalStatus} · " +
                    $"IP=[{(adapter.Addresses.Count == 0 ? "无" : string.Join(", ", adapter.Addresses))}] · " +
                    $"DNS=[{(adapter.DnsServers.Count == 0 ? "无" : string.Join(", ", adapter.DnsServers))}]");
            }
        }
        report.AppendLine("系统 DNS resolver 查询（本次导出时，结果会随网络变化）：");
        foreach (var host in HostResolutions)
            report.AppendLine("  " + host.Format());
        report.AppendLine("注意：查询使用 Windows 当前系统 resolver；服务器列表来自活动网卡配置，NRPT/VPN 等策略可能改变具体查询路径。此快照不更改系统 DNS，也不证明 Codex 的每个请求都使用相同解析结果。");
        return report.ToString();
    }
}

internal static class NetworkDiagnosticsCollector
{
    private static readonly string[] Hosts = ["chatgpt.com", "api.openai.com"];

    public static async Task<NetworkDiagnosticsSnapshot> CaptureAsync(CancellationToken cancellationToken = default)
    {
        var adapters = new List<NetworkInterfaceDiagnostic>();
        var dnsServers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces())
            {
                try
                {
                    var properties = networkInterface.GetIPProperties();
                    var addresses = properties.UnicastAddresses
                        .Select(item => item.Address.ToString())
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .OrderBy(item => item, StringComparer.OrdinalIgnoreCase)
                        .ToArray();
                    var perInterfaceDns = properties.DnsAddresses
                        .Select(address => address.ToString())
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .OrderBy(item => item, StringComparer.OrdinalIgnoreCase)
                        .ToArray();
                    if (networkInterface.OperationalStatus == OperationalStatus.Up)
                    {
                        foreach (var dns in perInterfaceDns)
                            dnsServers.Add(dns);
                    }

                    adapters.Add(new NetworkInterfaceDiagnostic(
                        networkInterface.Name,
                        networkInterface.NetworkInterfaceType.ToString(),
                        networkInterface.OperationalStatus.ToString(),
                        addresses,
                        perInterfaceDns));
                }
                catch (Exception ex) when (ex is NetworkInformationException or InvalidOperationException or System.Security.SecurityException)
                {
                    adapters.Add(new NetworkInterfaceDiagnostic(
                        networkInterface.Name,
                        networkInterface.NetworkInterfaceType.ToString(),
                        "读取失败（" + ex.GetType().Name + "）",
                        Array.Empty<string>(),
                        Array.Empty<string>()));
                }
            }
        }
        catch (Exception ex) when (ex is NetworkInformationException or InvalidOperationException or System.Security.SecurityException)
        {
            adapters.Clear();
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(3));
        var resolutions = await Task.WhenAll(Hosts.Select(host => ResolveAsync(host, timeout.Token))).ConfigureAwait(false);
        return new NetworkDiagnosticsSnapshot(
            DateTimeOffset.Now,
            NetworkInterface.GetIsNetworkAvailable(),
            dnsServers.OrderBy(item => item, StringComparer.OrdinalIgnoreCase).ToArray(),
            adapters,
            resolutions);
    }

    private static async Task<HostDnsDiagnostic> ResolveAsync(string host, CancellationToken cancellationToken)
    {
        var timer = Stopwatch.StartNew();
        try
        {
            var addresses = await Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);
            return new HostDnsDiagnostic(
                host,
                addresses.Length == 0 ? "NoRecord" : "Resolved via system DNS resolver",
                addresses.Where(address => address.AddressFamily == AddressFamily.InterNetwork)
                    .Select(address => address.ToString()).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                addresses.Where(address => address.AddressFamily == AddressFamily.InterNetworkV6)
                    .Select(address => address.ToString()).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                timer.Elapsed.TotalMilliseconds);
        }
        catch (OperationCanceledException)
        {
            return new HostDnsDiagnostic(host, cancellationToken.IsCancellationRequested ? "Cancelled/Timeout" : "Timeout", [], [], timer.Elapsed.TotalMilliseconds);
        }
        catch (SocketException ex)
        {
            return new HostDnsDiagnostic(host, "SocketError/" + ex.SocketErrorCode, [], [], timer.Elapsed.TotalMilliseconds);
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.Security.SecurityException)
        {
            return new HostDnsDiagnostic(host, "Error/" + ex.GetType().Name, [], [], timer.Elapsed.TotalMilliseconds);
        }
    }
}
