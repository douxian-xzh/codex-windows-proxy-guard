using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace CodexProxyManager.Services;

internal enum ProxyEndpointType
{
    PortOpen,
    HttpProxy,
    Socks5,
    MixedPort,
    Unreachable,
    Unknown
}

internal sealed record ProxyEndpointCandidate(ProxyEndpoint Endpoint, string Source, int Priority);

internal sealed record HttpConnectProbeResult(
    bool TcpConnected,
    bool ProxyProtocolIdentified,
    bool Success,
    int? StatusCode,
    string Stage,
    string Summary);

internal sealed record ProxyEndpointProbeResult(
    ProxyEndpoint Endpoint,
    string Source,
    ProxyEndpointType Type,
    bool TcpConnected,
    bool Socks5ProtocolIdentified,
    bool Socks5Usable,
    string Socks5Stage,
    bool HttpProxyProtocolIdentified,
    bool HttpConnectUsable,
    int? HttpStatusCode,
    string Detail);

/// <summary>
/// Detects configured and a small, fixed set of local proxy endpoints. It never changes system proxy,
/// environment variables, routing, DNS, firewall, or proxy-client modes.
/// </summary>
internal static class ProxyEndpointDetector
{
    private const int MaximumCandidates = 9;
    private const string ProbeDestinationHost = "api.openai.com";
    private const int ProbeDestinationPort = 443;

    private static readonly (int Port, string Source)[] CommonLoopbackPorts =
    [
        (7890, "常见代理端口（协议实测）"),
        (7891, "常见 SOCKS 端口（协议实测）"),
        (7892, "常见 mixed 端口（协议实测）"),
        (7897, "本项目历史代理端口（协议实测）"),
        (1080, "常见 SOCKS 端口"),
        (10808, "常见本地代理端口")
    ];

    public static IReadOnlyList<ProxyEndpointCandidate> BuildCandidates(
        ProxyEndpoint? currentInput,
        AppSettings? settings,
        SystemProxyInfo? systemProxy,
        bool currentInputDirty = false)
    {
        var candidates = new List<ProxyEndpointCandidate>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void Add(ProxyEndpoint? endpoint, string source)
        {
            if (endpoint is null || candidates.Count >= MaximumCandidates)
                return;
            var key = NormalizeEndpointKey(endpoint);
            if (seen.Add(key))
                candidates.Add(new ProxyEndpointCandidate(endpoint, source, candidates.Count));
        }

        if (currentInputDirty)
            Add(currentInput, "当前未保存输入");

        if (settings is { FollowSystemProxy: false }
            && settings.CustomHost is not null
            && settings.CustomPort is not null
            && ProxyEndpoint.TryCreate(settings.CustomHost, settings.CustomPort.Value.ToString(CultureInfo.InvariantCulture), out var saved, out _))
            Add(saved, "已保存的自定义端点");

        if (systemProxy is { Enabled: true, Endpoint: not null })
            Add(systemProxy.Endpoint, "Windows 固定系统代理");

        Add(currentInput, "当前输入端点");

        foreach (var (port, source) in CommonLoopbackPorts)
            Add(new ProxyEndpoint("127.0.0.1", port), source);

        return candidates;
    }

    public static async Task<IReadOnlyList<ProxyEndpointProbeResult>> DetectCandidatesAsync(
        ProxyEndpoint? currentInput,
        AppSettings? settings,
        SystemProxyInfo? systemProxy,
        bool currentInputDirty,
        TimeSpan timeoutPerProtocol,
        CancellationToken cancellationToken = default)
    {
        var candidates = BuildCandidates(currentInput, settings, systemProxy, currentInputDirty);
        using var concurrency = new SemaphoreSlim(3, 3);
        var tasks = candidates.Select(async candidate =>
        {
            await concurrency.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                return await ProbeEndpointAsync(candidate.Endpoint, candidate.Source, timeoutPerProtocol, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                concurrency.Release();
            }
        }).ToArray();

        return await Task.WhenAll(tasks).ConfigureAwait(false);
    }

    public static async Task<ProxyEndpointProbeResult> ProbeEndpointAsync(
        ProxyEndpoint endpoint,
        string source,
        TimeSpan timeoutPerProtocol,
        CancellationToken cancellationToken = default)
    {
        var socks = await Socks5ProxyProbe.ProbeAsync(
            endpoint,
            ProbeDestinationHost,
            ProbeDestinationPort,
            validateTls: false,
            tlsServerName: null,
            timeoutPerProtocol,
            cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();

        var http = await ProbeHttpConnectAsync(endpoint, timeoutPerProtocol, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();

        var endpointType = Classify(socks, http);
        var details = new List<string>
        {
            $"SOCKS5={socks.Stage}{(socks.Success ? "/CONNECT通过" : "/未通过")}",
            http.StatusCode is null
                ? $"HTTP={http.Stage}"
                : $"HTTP={http.StatusCode.Value}"
        };
        if (!string.IsNullOrWhiteSpace(socks.Summary))
            details.Add(socks.Summary);
        if (!string.IsNullOrWhiteSpace(http.Summary))
            details.Add(http.Summary);

        return new ProxyEndpointProbeResult(
            endpoint,
            source,
            endpointType,
            socks.TcpConnected || http.TcpConnected,
            socks.Socks5ProtocolIdentified,
            socks.Success,
            socks.Stage,
            http.ProxyProtocolIdentified,
            http.Success,
            http.StatusCode,
            string.Join("；", details));
    }

    internal static ProxyEndpointType Classify(Socks5ProbeResult socks, HttpConnectProbeResult http)
    {
        if (socks.Socks5ProtocolIdentified && http.ProxyProtocolIdentified)
            return ProxyEndpointType.MixedPort;
        if (socks.Socks5ProtocolIdentified)
            return ProxyEndpointType.Socks5;
        if (http.ProxyProtocolIdentified)
            return ProxyEndpointType.HttpProxy;
        if (http.Stage == "HttpResponse")
            return ProxyEndpointType.Unknown;
        if (socks.TcpConnected || http.TcpConnected)
            return ProxyEndpointType.PortOpen;
        if (socks.Stage is "Timeout" or "Cancelled" || http.Stage is "Timeout" or "Cancelled")
            return ProxyEndpointType.Unknown;
        return ProxyEndpointType.Unreachable;
    }

    private static async Task<HttpConnectProbeResult> ProbeHttpConnectAsync(
        ProxyEndpoint endpoint,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        bounded.CancelAfter(timeout);
        var token = bounded.Token;
        var tcpConnected = false;
        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(endpoint.Host, endpoint.Port, token).ConfigureAwait(false);
            tcpConnected = true;
            await using var stream = client.GetStream();
            var request = Encoding.ASCII.GetBytes(
                $"CONNECT {ProbeDestinationHost}:{ProbeDestinationPort} HTTP/1.1\r\nHost: {ProbeDestinationHost}:{ProbeDestinationPort}\r\nProxy-Connection: close\r\n\r\n");
            await stream.WriteAsync(request, token).ConfigureAwait(false);
            var statusLine = await ReadStatusLineAsync(stream, token).ConfigureAwait(false);
            if (!TryParseHttpStatus(statusLine, out var statusCode))
                return new HttpConnectProbeResult(true, false, false, null, "HttpResponse", "未收到可识别的 HTTP 代理状态行。");

            var proxyResponse = statusCode is 200 or 403 or 407 or 429 or 500 or 502 or 503 or 504 or 511;
            var success = statusCode is >= 200 and < 300;
            var summary = statusCode switch
            {
                200 => "HTTP CONNECT 通过。",
                407 => "检测到 HTTP 代理认证要求；本程序不会读取或发送认证信息。",
                _ when proxyResponse => $"收到 HTTP CONNECT 代理响应 {statusCode}；该状态不代表目标连接成功。",
                _ => $"收到 HTTP 响应 {statusCode}，不能确认其为可用代理。"
            };
            return new HttpConnectProbeResult(true, proxyResponse, success, statusCode, "HttpResponse", summary);
        }
        catch (OperationCanceledException)
        {
            return new HttpConnectProbeResult(tcpConnected, false, false, null,
                cancellationToken.IsCancellationRequested ? "Cancelled" : "Timeout",
                cancellationToken.IsCancellationRequested ? "HTTP 代理探测已取消。" : "HTTP 代理探测超时。");
        }
        catch (SocketException ex)
        {
            return new HttpConnectProbeResult(false, false, false, null, tcpConnected ? "HttpTransport" : "TcpConnect",
                $"HTTP 代理套接字失败：{ex.SocketErrorCode}。");
        }
        catch (IOException ex)
        {
            return new HttpConnectProbeResult(tcpConnected, false, false, null, "HttpTransport",
                $"HTTP 响应读取失败：{ex.GetType().Name}。");
        }
    }

    private static async Task<string> ReadStatusLineAsync(Stream stream, CancellationToken cancellationToken)
    {
        var bytes = new List<byte>(128);
        var one = new byte[1];
        while (bytes.Count < 512)
        {
            var read = await stream.ReadAsync(one, cancellationToken).ConfigureAwait(false);
            if (read == 0)
                throw new EndOfStreamException("HTTP peer closed before the status line.");
            if (one[0] == (byte)'\n')
                return Encoding.ASCII.GetString(bytes.ToArray()).TrimEnd('\r');
            bytes.Add(one[0]);
        }

        throw new InvalidDataException("HTTP status line exceeded the size limit.");
    }

    private static bool TryParseHttpStatus(string statusLine, out int statusCode)
    {
        statusCode = 0;
        var parts = statusLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return parts.Length >= 2
            && (parts[0] == "HTTP/1.0" || parts[0] == "HTTP/1.1")
            && int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out statusCode)
            && statusCode is >= 100 and <= 599;
    }

    private static string NormalizeEndpointKey(ProxyEndpoint endpoint)
    {
        var host = endpoint.Host.Trim().Trim('[', ']');
        if (IPAddress.TryParse(host, out var address))
            host = address.ToString();
        else
            host = host.TrimEnd('.').ToLowerInvariant();
        return $"{host}:{endpoint.Port.ToString(CultureInfo.InvariantCulture)}";
    }
}
