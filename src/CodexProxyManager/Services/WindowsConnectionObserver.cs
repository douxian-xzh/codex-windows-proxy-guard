using System.Net;
using System.Net.Sockets;

namespace CodexProxyManager.Services;

public sealed record ConnectionDisplayRow(
    string ProcessName,
    int ProcessId,
    string Protocol,
    string Endpoint,
    string State,
    string Route,
    string Evidence,
    DateTimeOffset FirstObservedAt,
    DateTimeOffset LastObservedAt)
{
    public string ObservedTime => $"{FirstObservedAt.ToLocalTime():HH:mm:ss} / {LastObservedAt.ToLocalTime():HH:mm:ss}";
}

public sealed record ConnectionObservation(
    DateTimeOffset CapturedAt,
    IReadOnlyList<ConnectionDisplayRow> Connections,
    int ProxyEndpointCount,
    int OtherNonProxyEndpointCount,
    int UnknownCount);

public sealed class WindowsConnectionObserver
{
    private readonly Dictionary<string, DateTimeOffset> _firstObserved = new(StringComparer.Ordinal);

    public ConnectionObservation Capture(TargetRuntimeSnapshot runtime)
    {
        var processes = runtime.Instances
            .SelectMany(instance => instance.Processes)
            .Concat(runtime.KnownComponentProcesses.Where(process => process.ExactRuleTargetPath))
            .GroupBy(process => process.ProcessId)
            .ToDictionary(group => group.Key, group => group.First());
        if (processes.Count == 0)
        {
            return new ConnectionObservation(DateTimeOffset.Now, Array.Empty<ConnectionDisplayRow>(), 0, 0, 0);
        }

        var connections = new List<ConnectionDisplayRow>();
        var capturedAt = DateTimeOffset.Now;
        foreach (var row in WindowsNativeSnapshot.ReadTcpConnections()
                     .Where(row => row.RemotePort > 0 && processes.ContainsKey(row.ProcessId)))
        {
            var process = processes[row.ProcessId];
            var endpoint = FormatEndpoint(row.RemoteAddress, row.RemotePort);
            connections.Add(new ConnectionDisplayRow(
                process.Name,
                row.ProcessId,
                "TCP",
                $"{FormatEndpoint(row.LocalAddress, row.LocalPort)} → {endpoint}",
                row.State,
                "原始目标端点",
                "Windows TCP 所有者表显示应用请求的远端端点；透明重定向不会把这里改成 SOCKS5 服务器地址。",
                capturedAt,
                capturedAt));
        }

        foreach (var row in WindowsNativeSnapshot.ReadUdpEndpoints()
                     .Where(row => processes.ContainsKey(row.ProcessId)))
        {
            var process = processes[row.ProcessId];
            connections.Add(new ConnectionDisplayRow(
                process.Name,
                row.ProcessId,
                "UDP",
                $"本地 {FormatEndpoint(row.LocalAddress, row.LocalPort)}",
                "Windows 表未提供远端",
                "远端未知",
                "Windows UDP 所有者表仅提供本地端点；此快照无法判断 UDP 远端或代理处理结果。",
                capturedAt,
                capturedAt));
        }

        var distinctConnections = connections
            .DistinctBy(connection => string.Join('|', connection.ProcessId, connection.Protocol, connection.Endpoint, connection.State))
            .Select(connection =>
            {
                var key = string.Join('|', connection.ProcessId, connection.Protocol, connection.Endpoint);
                if (!_firstObserved.TryGetValue(key, out var firstObservedAt))
                {
                    firstObservedAt = capturedAt;
                    _firstObserved[key] = firstObservedAt;
                }

                return connection with { FirstObservedAt = firstObservedAt, LastObservedAt = capturedAt };
            })
            .OrderBy(connection => connection.ProcessName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(connection => connection.ProcessId)
            .ThenBy(connection => connection.Protocol, StringComparer.Ordinal)
            .ThenBy(connection => connection.Endpoint, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var activeKeys = distinctConnections
            .Select(connection => string.Join('|', connection.ProcessId, connection.Protocol, connection.Endpoint))
            .ToHashSet(StringComparer.Ordinal);
        foreach (var staleKey in _firstObserved.Keys.Except(activeKeys).ToArray())
        {
            _firstObserved.Remove(staleKey);
        }

        return new ConnectionObservation(
            capturedAt,
            distinctConnections,
            0,
            0,
            distinctConnections.Count(connection => connection.Route == "远端未知"));
    }

    private static string FormatEndpoint(IPAddress address, int port) =>
        address.AddressFamily == AddressFamily.InterNetworkV6
            ? $"[{address}]:{port}"
            : $"{address}:{port}";
}
