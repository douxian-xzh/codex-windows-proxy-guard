using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;

if (args.Length != 1 || !Directory.Exists(args[0]))
{
    Console.Error.WriteLine("Pass the built NetworkProbe output directory.");
    return 2;
}

var outputRoot = Path.GetFullPath(args[0]);
var probeExe = Path.Combine(outputRoot, "NetworkProbe.exe");
if (!File.Exists(probeExe))
{
    Console.Error.WriteLine($"NetworkProbe.exe not found in {outputRoot}");
    return 2;
}

var runRoot = Path.Combine(Path.GetTempPath(), "CodexProxy-NetworkProbe-SelfTest", Guid.NewGuid().ToString("N"));
var targetDirectory = Path.Combine(runRoot, "Target");
var controlDirectory = Path.Combine(runRoot, "Control");
Directory.CreateDirectory(targetDirectory);
Directory.CreateDirectory(controlDirectory);
CopyProbe(outputRoot, targetDirectory);
CopyProbe(outputRoot, controlDirectory);

try
{
    await VerifyTcpAsync("Target", targetDirectory);
    await VerifyTcpAsync("Control", controlDirectory);
    await VerifyUdpEchoAsync("Target", targetDirectory);
    await VerifyUdpEchoAsync("Control", controlDirectory);
    if (Socket.OSSupportsIPv6)
    {
        await VerifyTcpAsync("Target IPv6", targetDirectory, IPAddress.IPv6Loopback);
        await VerifyTcpAsync("Control IPv6", controlDirectory, IPAddress.IPv6Loopback);
        await VerifyUdpEchoAsync("Target IPv6", targetDirectory, IPAddress.IPv6Loopback);
        await VerifyUdpEchoAsync("Control IPv6", controlDirectory, IPAddress.IPv6Loopback);
    }
    else
    {
        Console.WriteLine("NOTTESTED: IPv6 loopback is disabled on this host.");
    }

    var targetPath = Path.Combine(targetDirectory, "NetworkProbe.exe");
    var controlPath = Path.Combine(controlDirectory, "NetworkProbe.exe");
    if (string.Equals(targetPath, controlPath, StringComparison.OrdinalIgnoreCase))
    {
        throw new InvalidOperationException("Target and control executable paths are not distinct.");
    }

    Console.WriteLine("PASS: native-socket TCP and UDP echo work through distinct target/control paths on tested address families.");
    Console.WriteLine("LIMIT: ProxiFyre was not installed or started; this local harness does not prove transparent proxying or non-target routing.");
    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"FAIL: {ex.GetType().Name}: {ex.Message}");
    return 1;
}
finally
{
    try { Directory.Delete(runRoot, recursive: true); } catch (IOException) { }
}

static void CopyProbe(string sourceDirectory, string destinationDirectory)
{
    foreach (var file in Directory.EnumerateFiles(sourceDirectory))
    {
        File.Copy(file, Path.Combine(destinationDirectory, Path.GetFileName(file)), overwrite: true);
    }
}

static async Task VerifyTcpAsync(string label, string directory, IPAddress? destination = null)
{
    destination ??= IPAddress.Loopback;
    using var listener = new TcpListener(destination, 0);
    listener.Start();
    var endpoint = (IPEndPoint)listener.LocalEndpoint;
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(8));
    var acceptTask = listener.AcceptSocketAsync(timeout.Token);
    var reportTask = RunProbeAsync(directory, ["--mode", "tcp", "--ip", destination.ToString(), "--port", endpoint.Port.ToString()]);
    using var accepted = await acceptTask;
    accepted.Shutdown(SocketShutdown.Both);
    accepted.Close();
    var report = await reportTask;
    Assert(report.ExitCode == 0, $"{label} TCP probe exit was {report.ExitCode}: {report.StdErr}");
    using var document = JsonDocument.Parse(report.StdOut);
    Assert(document.RootElement.GetProperty("Status").GetString() == "TcpConnected", $"{label} TCP status mismatch.");
    Assert(document.RootElement.GetProperty("ReadsSystemProxy").GetBoolean() == false, "Probe claims it read system proxy.");
    Assert(document.RootElement.GetProperty("UsesNativeSocket").GetBoolean(), "Probe did not report native socket use.");
    Console.WriteLine($"PASS: {label} TCP loopback; path={document.RootElement.GetProperty("ExecutablePath").GetString()}");
}

static async Task VerifyUdpEchoAsync(string label, string directory, IPAddress? destination = null)
{
    destination ??= IPAddress.Loopback;
    using var server = new Socket(destination.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
    server.Bind(new IPEndPoint(destination, 0));
    var endpoint = (IPEndPoint)server.LocalEndPoint!;
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(8));
    var echoTask = Task.Run(async () =>
    {
        var buffer = new byte[1024];
        EndPoint remote = new IPEndPoint(destination.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);
        var received = await server.ReceiveFromAsync(buffer, SocketFlags.None, remote, timeout.Token);
        await server.SendToAsync(buffer.AsMemory(0, received.ReceivedBytes), SocketFlags.None, received.RemoteEndPoint, timeout.Token);
    }, timeout.Token);
    var report = await RunProbeAsync(directory,
        ["--mode", "udp-echo", "--ip", destination.ToString(), "--port", endpoint.Port.ToString(), "--timeout-ms", "5000"]);
    await echoTask;
    Assert(report.ExitCode == 0, $"{label} UDP probe exit was {report.ExitCode}: {report.StdErr}");
    using var document = JsonDocument.Parse(report.StdOut);
    Assert(document.RootElement.GetProperty("Status").GetString() == "UdpEchoPassed", $"{label} UDP status mismatch.");
    Console.WriteLine($"PASS: {label} UDP echo; path={document.RootElement.GetProperty("ExecutablePath").GetString()}");
}

static async Task<ProbeProcessResult> RunProbeAsync(string directory, IReadOnlyList<string> arguments)
{
    var startInfo = new ProcessStartInfo
    {
        FileName = Path.Combine(directory, "NetworkProbe.exe"),
        WorkingDirectory = directory,
        UseShellExecute = false,
        CreateNoWindow = true,
        RedirectStandardOutput = true,
        RedirectStandardError = true
    };
    foreach (var argument in arguments)
    {
        startInfo.ArgumentList.Add(argument);
    }

    using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Could not start NetworkProbe.");
    var stdoutTask = process.StandardOutput.ReadToEndAsync();
    var stderrTask = process.StandardError.ReadToEndAsync();
    await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(8));
    return new ProbeProcessResult(process.ExitCode, await stdoutTask, await stderrTask);
}

static void Assert(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
}

internal sealed record ProbeProcessResult(int ExitCode, string StdOut, string StdErr);
