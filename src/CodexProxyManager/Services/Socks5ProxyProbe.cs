using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Globalization;
using System.IO;
using System.Text;

namespace CodexProxyManager.Services;

internal sealed record Socks5ProbeResult(
    bool Success,
    bool TcpConnected,
    string Stage,
    string Summary,
    string? ReplyCode = null,
    string? TlsProtocol = null,
    string? CertificateSubject = null,
    double DurationMs = 0,
    bool Socks5ProtocolIdentified = false);

/// <summary>Performs a diagnostic SOCKS5 handshake only. It never changes system proxy or environment settings.</summary>
internal static class Socks5ProxyProbe
{
    public static async Task<Socks5ProbeResult> ProbeAsync(
        ProxyEndpoint endpoint,
        string destinationHost,
        int destinationPort,
        bool validateTls,
        string? tlsServerName,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        var timer = System.Diagnostics.Stopwatch.StartNew();
        if (string.IsNullOrWhiteSpace(destinationHost) || destinationPort is < 1 or > 65535)
            return new(false, false, "Input", "目标主机或端口无效。");
        if (validateTls && string.IsNullOrWhiteSpace(tlsServerName))
            return new(false, false, "Input", "TLS 探测需要明确的 SNI 主机名。");

        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        bounded.CancelAfter(timeout);
        var token = bounded.Token;
        var tcpConnected = false;
        var socks5ProtocolIdentified = false;
        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(endpoint.Host, endpoint.Port, token).ConfigureAwait(false);
            tcpConnected = true;
            await using var stream = client.GetStream();

            // Offer only no-auth. No credentials are accepted, generated, stored, or logged by this V1 probe.
            await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }, token).ConfigureAwait(false);
            var greeting = new byte[2];
            await ReadExactlyAsync(stream, greeting, token).ConfigureAwait(false);
            if (greeting[0] != 0x05)
                return Result(false, "SocksGreeting", "端点没有返回 SOCKS5 握手；可能是 HTTP 代理或其他协议。", tcpConnected, timer);
            socks5ProtocolIdentified = true;
            if (greeting[1] == 0xFF)
                return Result(false, "SocksAuthentication", "SOCKS5 端点未接受匿名方式；当前版本不支持认证凭据。", tcpConnected, timer, socks5ProtocolIdentified: true);
            if (greeting[1] != 0x00)
                return Result(false, "SocksAuthentication", $"SOCKS5 端点要求不支持的认证方法（方法码 {greeting[1]}）。", tcpConnected, timer, socks5ProtocolIdentified: true);

            var request = BuildConnectRequest(destinationHost, destinationPort);
            await stream.WriteAsync(request, token).ConfigureAwait(false);
            var reply = new byte[4];
            await ReadExactlyAsync(stream, reply, token).ConfigureAwait(false);
            if (reply[0] != 0x05 || reply[2] != 0x00)
                return Result(false, "SocksReply", "SOCKS5 CONNECT 响应格式无效。", tcpConnected, timer, socks5ProtocolIdentified: true);

            var addressLength = reply[3] switch
            {
                0x01 => 4,
                0x04 => 16,
                0x03 => await ReadDomainLengthAsync(stream, token).ConfigureAwait(false),
                _ => -1
            };
            if (addressLength < 0)
                return Result(false, "SocksReply", "SOCKS5 返回了不支持的地址类型。", tcpConnected, timer, socks5ProtocolIdentified: true);
            var tail = new byte[addressLength + 2];
            await ReadExactlyAsync(stream, tail, token).ConfigureAwait(false);

            if (reply[1] != 0x00)
                return Result(false, "SocksConnect", DescribeReply(reply[1]), tcpConnected, timer, ReplyName(reply[1]), socks5ProtocolIdentified: true);

            if (validateTls)
            {
                using var tls = new SslStream(stream, leaveInnerStreamOpen: true);
                await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = tlsServerName!,
                    CertificateRevocationCheckMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.Online
                }, token).ConfigureAwait(false);
                return new Socks5ProbeResult(
                    true, true, "Tls", "SOCKS5 CONNECT 与 TLS 证书校验均通过；这不代表 Responses WebSocket 或 Remote 已通过。",
                    ReplyName(reply[1]), tls.SslProtocol.ToString(), tls.RemoteCertificate?.Subject, timer.Elapsed.TotalMilliseconds, true);
            }

            return Result(true, "SocksConnect", "SOCKS5 匿名握手与目标 CONNECT 通过；不代表最终业务 WebSocket 已通过。", tcpConnected, timer, ReplyName(reply[1]), socks5ProtocolIdentified: true);
        }
        catch (OperationCanceledException)
        {
            return new Socks5ProbeResult(false, tcpConnected, cancellationToken.IsCancellationRequested ? "Cancelled" : "Timeout",
                cancellationToken.IsCancellationRequested ? "探测已取消。" : "探测超时。", DurationMs: timer.Elapsed.TotalMilliseconds,
                Socks5ProtocolIdentified: socks5ProtocolIdentified);
        }
        catch (AuthenticationException)
        {
            return new(false, tcpConnected, "TlsValidation", "SOCKS5 CONNECT 已建立，但 TLS 握手或证书校验失败。", DurationMs: timer.Elapsed.TotalMilliseconds,
                Socks5ProtocolIdentified: socks5ProtocolIdentified);
        }
        catch (SocketException ex)
        {
            return new(false, tcpConnected, tcpConnected ? "SocksTransport" : "TcpConnect", $"网络套接字失败：{ex.SocketErrorCode}。", DurationMs: timer.Elapsed.TotalMilliseconds,
                Socks5ProtocolIdentified: socks5ProtocolIdentified);
        }
        catch (IOException ex)
        {
            return new(false, tcpConnected, "SocksTransport", $"SOCKS5 响应读取失败：{ex.GetType().Name}。", DurationMs: timer.Elapsed.TotalMilliseconds,
                Socks5ProtocolIdentified: socks5ProtocolIdentified);
        }
        catch (ArgumentException)
        {
            return new(false, tcpConnected, "Input", "SOCKS5 探测目标格式无效。", DurationMs: timer.Elapsed.TotalMilliseconds);
        }
    }

    private static byte[] BuildConnectRequest(string destinationHost, int port)
    {
        byte[] address;
        byte addressType;
        if (IPAddress.TryParse(destinationHost, out var ip))
        {
            address = ip.GetAddressBytes();
            addressType = ip.AddressFamily == AddressFamily.InterNetwork ? (byte)0x01 : (byte)0x04;
        }
        else
        {
            var asciiHost = new IdnMapping().GetAscii(destinationHost.TrimEnd('.'));
            address = Encoding.ASCII.GetBytes(asciiHost);
            if (address.Length is 0 or > 255)
                throw new ArgumentException("SOCKS5 domain name length must be 1..255.");
            addressType = 0x03;
        }

        var offset = addressType == 0x03 ? 5 : 4;
        var request = new byte[offset + address.Length + 2];
        request[0] = 0x05;
        request[1] = 0x01;
        request[2] = 0x00;
        request[3] = addressType;
        if (addressType == 0x03) request[4] = (byte)address.Length;
        Buffer.BlockCopy(address, 0, request, offset, address.Length);
        request[^2] = (byte)(port >> 8);
        request[^1] = (byte)port;
        return request;
    }

    private static async Task<int> ReadDomainLengthAsync(Stream stream, CancellationToken token)
    {
        var length = new byte[1];
        await ReadExactlyAsync(stream, length, token).ConfigureAwait(false);
        return length[0];
    }

    private static async Task ReadExactlyAsync(Stream stream, Memory<byte> buffer, CancellationToken token)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer[offset..], token).ConfigureAwait(false);
            if (read == 0) throw new EndOfStreamException("SOCKS5 peer closed the connection early.");
            offset += read;
        }
    }

    private static string DescribeReply(byte reply) => reply switch
    {
        0x01 => "SOCKS5 代理报告通用故障。",
        0x02 => "SOCKS5 代理策略拒绝了该请求。",
        0x03 => "SOCKS5 代理无法连接目标网络。",
        0x04 => "SOCKS5 代理无法解析或访问目标主机。",
        0x05 => "SOCKS5 代理拒绝连接目标主机。",
        0x06 => "SOCKS5 目标 TTL 已过期。",
        0x07 => "SOCKS5 代理不支持 CONNECT 命令。",
        0x08 => "SOCKS5 代理不支持目标地址类型。",
        _ => $"SOCKS5 代理返回未知错误码 0x{reply:X2}。"
    };

    private static string ReplyName(byte reply) => reply == 0 ? "Succeeded" : $"Reply0x{reply:X2}";

    private static Socks5ProbeResult Result(
        bool success,
        string stage,
        string summary,
        bool tcp,
        System.Diagnostics.Stopwatch timer,
        string? reply = null,
        bool socks5ProtocolIdentified = false) =>
        new(success, tcp, stage, summary, reply, DurationMs: timer.Elapsed.TotalMilliseconds,
            Socks5ProtocolIdentified: socks5ProtocolIdentified);
}
