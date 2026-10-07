using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine("NetworkProbe is intended for Windows transparent-routing tests.");
    return 2;
}

if (args is ["--help"] or ["-h"])
{
    Console.WriteLine(ProbeOptions.Usage);
    return 0;
}

if (!ProbeOptions.TryParse(args, out var options, out var parseError))
{
    Console.Error.WriteLine(parseError);
    Console.Error.WriteLine(ProbeOptions.Usage);
    return 2;
}

using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(options!.TimeoutMs));
Console.CancelKeyPress += (_, eventArgs) =>
{
    eventArgs.Cancel = true;
    cancellation.Cancel();
};

var runId = Guid.NewGuid().ToString("N");
var started = Stopwatch.GetTimestamp();
string result;
string? detail = null;
string? certificateSubject = null;
int? certificateProtocol = null;

try
{
    var endpoint = new IPEndPoint(options.Destination, options.Port);
    switch (options.Mode)
    {
        case ProbeMode.Tcp:
            using (var socket = new Socket(options.Destination.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
                   { NoDelay = true })
            {
                await socket.ConnectAsync(endpoint, cancellation.Token);
            }
            result = "TcpConnected";
            break;

        case ProbeMode.Tls:
            using (var socket = new Socket(options.Destination.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
                   { NoDelay = true })
            {
                await socket.ConnectAsync(endpoint, cancellation.Token);
                using var network = new NetworkStream(socket, ownsSocket: false);
                using var tls = new SslStream(network, leaveInnerStreamOpen: true);
                await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = options.ServerName!,
                    EnabledSslProtocols = SslProtocols.None,
                    CertificateRevocationCheckMode = X509RevocationMode.Online
                }, cancellation.Token);
                certificateSubject = tls.RemoteCertificate?.Subject;
                certificateProtocol = (int)tls.SslProtocol;
            }
            result = "TlsValidated";
            break;

        case ProbeMode.UdpEcho:
            var payload = System.Text.Encoding.ASCII.GetBytes($"NetworkProbe:{runId}");
            using (var socket = new Socket(options.Destination.AddressFamily, SocketType.Dgram, ProtocolType.Udp))
            {
                await socket.SendToAsync(payload, SocketFlags.None, endpoint, cancellation.Token);
                var response = new byte[1024];
                EndPoint remote = options.Destination.AddressFamily == AddressFamily.InterNetwork
                    ? new IPEndPoint(IPAddress.Any, 0)
                    : new IPEndPoint(IPAddress.IPv6Any, 0);
                var received = await socket.ReceiveFromAsync(response, SocketFlags.None, remote, cancellation.Token);
                if (!response.AsSpan(0, received.ReceivedBytes).SequenceEqual(payload))
                {
                    throw new InvalidDataException("UDP echo payload did not match this run's nonce.");
                }
            }
            result = "UdpEchoPassed";
            break;

        default:
            throw new InvalidOperationException("Unsupported probe mode.");
    }
}
catch (OperationCanceledException)
{
    result = "CancelledOrTimedOut";
}
catch (AuthenticationException ex)
{
    result = "TlsFailed";
    detail = ex.GetType().Name;
}
catch (SocketException ex)
{
    result = "SocketFailed";
    detail = ex.SocketErrorCode.ToString();
}
catch (Exception ex) when (ex is IOException or InvalidDataException or InvalidOperationException)
{
    result = "ProbeFailed";
    detail = ex.GetType().Name;
}

var process = Process.GetCurrentProcess();
DateTimeOffset? processStarted = null;
try
{
    processStarted = process.StartTime;
}
catch (InvalidOperationException)
{
    // Process identity remains useful even if creation time is unavailable.
}

var report = new ProbeReport(
    SchemaVersion: 1,
    RunId: runId,
    TimestampUtc: DateTimeOffset.UtcNow,
    Mode: options.Mode.ToString(),
    Status: result,
    ProcessId: Environment.ProcessId,
    ProcessCreatedAt: processStarted,
    ExecutablePath: Environment.ProcessPath,
    DestinationIp: options.Destination.ToString(),
    DestinationPort: options.Port,
    ServerName: options.ServerName,
    DurationMs: Stopwatch.GetElapsedTime(started).TotalMilliseconds,
    UsesNativeSocket: true,
    ReadsSystemProxy: false,
    ReadsProxyEnvironment: false,
    CertificateSubject: certificateSubject,
    TlsProtocol: certificateProtocol,
    Detail: detail);

Console.WriteLine(JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
return result is "TcpConnected" or "TlsValidated" or "UdpEchoPassed" ? 0 : 1;

internal enum ProbeMode
{
    Tcp,
    Tls,
    UdpEcho
}

internal sealed record ProbeOptions(ProbeMode Mode, IPAddress Destination, int Port, string? ServerName, int TimeoutMs)
{
    public const string Usage = "Usage: NetworkProbe --mode tcp|tls|udp-echo --ip <literal-ip> --port <1..65535> [--sni <dns-name>] [--timeout-ms <100..30000>]";

    public static bool TryParse(string[] args, out ProbeOptions? options, out string error)
    {
        options = null;
        error = string.Empty;
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < args.Length; index++)
        {
            if (!args[index].StartsWith("--", StringComparison.Ordinal) || index + 1 >= args.Length)
            {
                error = "Arguments must be named options with a value.";
                return false;
            }

            var key = args[index][2..];
            if (!values.TryAdd(key, args[++index]))
            {
                error = $"Duplicate option --{key}.";
                return false;
            }
        }

        if (!values.TryGetValue("mode", out var modeText)
            || !Enum.TryParse<ProbeMode>(modeText.Replace("-", string.Empty), ignoreCase: true, out var mode))
        {
            error = "Choose mode tcp, tls, or udp-echo.";
            return false;
        }

        if (!values.TryGetValue("ip", out var ipText) || !IPAddress.TryParse(ipText, out var ip))
        {
            error = "--ip must be an IPv4 or IPv6 literal; hostname resolution is intentionally excluded from this route probe.";
            return false;
        }

        if (!values.TryGetValue("port", out var portText) || !int.TryParse(portText, out var port) || port is < 1 or > 65535)
        {
            error = "--port must be an integer from 1 to 65535.";
            return false;
        }

        var timeout = 5000;
        if (values.TryGetValue("timeout-ms", out var timeoutText)
            && (!int.TryParse(timeoutText, out timeout) || timeout is < 100 or > 30000))
        {
            error = "--timeout-ms must be an integer from 100 to 30000.";
            return false;
        }

        var serverName = values.GetValueOrDefault("sni");
        if (mode == ProbeMode.Tls && string.IsNullOrWhiteSpace(serverName))
        {
            error = "TLS mode requires --sni so certificate validation uses the intended host name.";
            return false;
        }

        if (values.Keys.Any(key => key is not ("mode" or "ip" or "port" or "sni" or "timeout-ms")))
        {
            error = "An unsupported option was supplied.";
            return false;
        }

        options = new ProbeOptions(mode, ip, port, serverName, timeout);
        return true;
    }
}

internal sealed record ProbeReport(
    int SchemaVersion,
    string RunId,
    DateTimeOffset TimestampUtc,
    string Mode,
    string Status,
    int ProcessId,
    DateTimeOffset? ProcessCreatedAt,
    string? ExecutablePath,
    string DestinationIp,
    int DestinationPort,
    string? ServerName,
    double DurationMs,
    bool UsesNativeSocket,
    bool ReadsSystemProxy,
    bool ReadsProxyEnvironment,
    string? CertificateSubject,
    int? TlsProtocol,
    string? Detail);
