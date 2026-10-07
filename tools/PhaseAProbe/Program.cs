using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;
using Microsoft.Win32;

if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine("This probe only runs on Windows.");
    return 2;
}

Console.WriteLine("Codex Proxy Phase A Probe (read-only)");
Console.WriteLine($"Captured: {DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}");
Console.WriteLine();

var proxy = ReadProxySettings();
Console.WriteLine("Current-user Windows proxy:");
Console.WriteLine($"  Enabled: {proxy.Enabled}");
Console.WriteLine($"  Server: {SanitizeProxy(proxy.Server)}");
Console.WriteLine($"  PAC configured: {proxy.HasPac}");
Console.WriteLine($"  Auto detect: {proxy.AutoDetect}");
Console.WriteLine($"  Bypass entries: {proxy.BypassCount}; includes <local>: {proxy.IncludesLocal}");
Console.WriteLine();

var processes = NativeMethods.ReadProcesses();
var chatGptRoots = processes.Values
    .Where(p => string.Equals(p.Name, "ChatGPT.exe", StringComparison.OrdinalIgnoreCase))
    .Where(p => !processes.TryGetValue(p.ParentPid, out var parent)
        || !string.Equals(parent.Name, "ChatGPT.exe", StringComparison.OrdinalIgnoreCase))
    .OrderBy(p => p.Pid)
    .ToArray();

if (chatGptRoots.Length == 0)
{
    Console.WriteLine("No ChatGPT.exe process was found.");
    return 0;
}

var tcpRows = NativeMethods.ReadTcpRows();
var udpRows = NativeMethods.ReadUdpRows();
var proxyEndpoints = proxy.Enabled
    ? ResolveProxyEndpoints(proxy.Server)
    : new HashSet<(string Address, int Port)>();

foreach (var root in chatGptRoots)
{
    var owned = GetDescendantPids(root.Pid, processes);
    Console.WriteLine($"Target process tree: ChatGPT.exe PID {root.Pid}");
    Console.WriteLine($"  Processes: {owned.Count}");
    foreach (var process in owned.Select(id => processes[id]).OrderBy(p => p.Pid))
    {
        Console.WriteLine($"    {process.Name,-32} PID={process.Pid,-7} Parent={process.ParentPid}");
    }

    Console.WriteLine("  TCP remote endpoints:");
    var ownedTcp = tcpRows.Where(row => owned.Contains(row.Pid) && row.RemotePort != 0)
        .OrderBy(row => row.Pid)
        .ThenBy(row => row.RemoteAddress.ToString())
        .ThenBy(row => row.RemotePort)
        .ToArray();

    if (ownedTcp.Length == 0)
    {
        Console.WriteLine("    (none observed)");
    }
    else
    {
        foreach (var group in ownedTcp.GroupBy(row => new
                 {
                     row.Pid,
                     Address = row.RemoteAddress.ToString(),
                     row.RemotePort,
                     row.State
                 })
                 .OrderBy(group => group.Key.Pid)
                 .ThenBy(group => group.Key.Address)
                 .ThenBy(group => group.Key.RemotePort))
        {
            var route = proxyEndpoints.Contains((group.Key.Address, group.Key.RemotePort))
                ? "proxy endpoint match"
                : "unclassified endpoint";
            Console.WriteLine($"    PID={group.Key.Pid,-7} {group.Key.Address}:{group.Key.RemotePort,-5} {group.Key.State,-12} {route} ({group.Count()})");
        }
    }

    Console.WriteLine("  UDP local endpoints:");
    var ownedUdp = udpRows.Where(row => owned.Contains(row.Pid))
        .OrderBy(row => row.Pid)
        .ThenBy(row => row.LocalAddress.ToString())
        .ThenBy(row => row.LocalPort)
        .ToArray();

    if (ownedUdp.Length == 0)
    {
        Console.WriteLine("    (none observed)");
    }
    else
    {
        foreach (var group in ownedUdp.GroupBy(row => new
                 {
                     row.Pid,
                     Address = row.LocalAddress.ToString(),
                     row.LocalPort
                 })
                 .OrderBy(group => group.Key.Pid)
                 .ThenBy(group => group.Key.Address)
                 .ThenBy(group => group.Key.LocalPort))
        {
            Console.WriteLine($"    PID={group.Key.Pid,-7} {group.Key.Address}:{group.Key.LocalPort} ({group.Count()})");
        }
    }

    Console.WriteLine();
}

Console.WriteLine("Notes:");
Console.WriteLine("  - A proxy endpoint match only confirms a socket to that endpoint.");
Console.WriteLine("  - Other TCP endpoints are unclassified; this probe does not claim they are direct.");
Console.WriteLine("  - UDP rows expose local endpoints only; this probe cannot infer the remote peer.");
Console.WriteLine("  - This probe does not launch, stop, or modify any process or proxy setting.");
return 0;

static ProxySettings ReadProxySettings()
{
    using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
    var server = key?.GetValue("ProxyServer") as string ?? string.Empty;
    var bypass = key?.GetValue("ProxyOverride") as string ?? string.Empty;
    return new ProxySettings(
        Enabled: Convert.ToInt32(key?.GetValue("ProxyEnable") ?? 0) != 0,
        Server: server,
        HasPac: !string.IsNullOrWhiteSpace(key?.GetValue("AutoConfigURL") as string),
        AutoDetect: Convert.ToInt32(key?.GetValue("AutoDetect") ?? 0) != 0,
        BypassCount: bypass.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Length,
        IncludesLocal: bypass.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Any(value => string.Equals(value, "<local>", StringComparison.OrdinalIgnoreCase)));
}

static string SanitizeProxy(string value) =>
    System.Text.RegularExpressions.Regex.Replace(value, @"(?i)(https?://|socks5?://)[^/@;]+@", "$1***@");

static HashSet<(string Address, int Port)> ResolveProxyEndpoints(string proxyServer)
{
    var result = new HashSet<(string Address, int Port)>();
    if (string.IsNullOrWhiteSpace(proxyServer))
    {
        return result;
    }

    var entries = proxyServer.Contains('=')
        ? proxyServer.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(entry => entry[(entry.IndexOf('=') + 1)..])
        : [proxyServer];

    foreach (var entry in entries)
    {
        var candidate = entry.Trim();
        if (candidate.Contains("://", StringComparison.Ordinal))
        {
            if (!Uri.TryCreate(candidate, UriKind.Absolute, out var uri))
            {
                continue;
            }

            AddAddresses(uri.Host, uri.Port, result);
            continue;
        }

        if (candidate.StartsWith("[", StringComparison.Ordinal))
        {
            var closingBracket = candidate.IndexOf(']');
            if (closingBracket > 0 && closingBracket + 2 < candidate.Length
                && int.TryParse(candidate[(closingBracket + 2)..], out var ipv6Port))
            {
                AddAddresses(candidate[1..closingBracket], ipv6Port, result);
            }

            continue;
        }

        var separator = candidate.LastIndexOf(':');
        if (separator > 0 && int.TryParse(candidate[(separator + 1)..], out var port))
        {
            AddAddresses(candidate[..separator], port, result);
        }
    }

    return result;
}

static void AddAddresses(string host, int port, HashSet<(string Address, int Port)> target)
{
    if (port is < 1 or > 65535)
    {
        return;
    }

    if (IPAddress.TryParse(host, out var literal))
    {
        target.Add((literal.ToString(), port));
    }
}

static HashSet<int> GetDescendantPids(int rootPid, IReadOnlyDictionary<int, ProcessInfo> processes)
{
    var result = new HashSet<int> { rootPid };
    var pending = new Queue<int>();
    pending.Enqueue(rootPid);
    while (pending.TryDequeue(out var parentPid))
    {
        foreach (var child in processes.Values.Where(process => process.ParentPid == parentPid))
        {
            if (result.Add(child.Pid))
            {
                pending.Enqueue(child.Pid);
            }
        }
    }

    return result;
}

static class NativeMethods
{
    private const int ErrorInsufficientBuffer = 122;
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int TcpTableOwnerPidAll = 5;
    private const int UdpTableOwnerPid = 1;
    private const uint Th32csSnapProcess = 0x00000002;

    public static Dictionary<int, ProcessInfo> ReadProcesses()
    {
        var snapshot = CreateToolhelp32Snapshot(Th32csSnapProcess, 0);
        if (snapshot == IntPtr.Zero || snapshot == new IntPtr(-1))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        try
        {
            var entry = new ProcessEntry32 { Size = (uint)Marshal.SizeOf<ProcessEntry32>() };
            var result = new Dictionary<int, ProcessInfo>();
            if (!Process32FirstW(snapshot, ref entry))
            {
                return result;
            }

            do
            {
                result[(int)entry.ProcessId] = new ProcessInfo(
                    (int)entry.ProcessId,
                    (int)entry.ParentProcessId,
                    entry.ExecutableFile);
                entry.Size = (uint)Marshal.SizeOf<ProcessEntry32>();
            }
            while (Process32NextW(snapshot, ref entry));

            return result;
        }
        finally
        {
            CloseHandle(snapshot);
        }
    }

    public static IReadOnlyList<TcpInfo> ReadTcpRows()
    {
        var rows = new List<TcpInfo>();
        rows.AddRange(ReadTcpFamily(AfInet));
        rows.AddRange(ReadTcpFamily(AfInet6));
        return rows;
    }

    public static IReadOnlyList<UdpInfo> ReadUdpRows()
    {
        var rows = new List<UdpInfo>();
        rows.AddRange(ReadUdpFamily(AfInet));
        rows.AddRange(ReadUdpFamily(AfInet6));
        return rows;
    }

    private static IEnumerable<TcpInfo> ReadTcpFamily(int family)
    {
        var table = ReadTable((IntPtr buffer, ref int size) => GetExtendedTcpTable(
            buffer, ref size, true, family, TcpTableOwnerPidAll, 0));
        if (table == IntPtr.Zero)
        {
            yield break;
        }

        try
        {
            var count = Marshal.ReadInt32(table);
            var rowSize = family == AfInet ? 24 : 56;
            for (var index = 0; index < count; index++)
            {
                var row = IntPtr.Add(table, sizeof(uint) + (index * rowSize));
                var state = Marshal.ReadInt32(row);
                IPAddress localAddress;
                int localPort;
                IPAddress remoteAddress;
                int remotePort;
                int pid;

                if (family == AfInet)
                {
                    localAddress = new IPAddress(BitConverter.GetBytes(unchecked((uint)Marshal.ReadInt32(row, 4))));
                    localPort = DecodePort(unchecked((uint)Marshal.ReadInt32(row, 8)));
                    remoteAddress = new IPAddress(BitConverter.GetBytes(unchecked((uint)Marshal.ReadInt32(row, 12))));
                    remotePort = DecodePort(unchecked((uint)Marshal.ReadInt32(row, 16)));
                    pid = Marshal.ReadInt32(row, 20);
                }
                else
                {
                    localAddress = ReadIpV6(row, 0, Marshal.ReadInt32(row, 16));
                    localPort = DecodePort(unchecked((uint)Marshal.ReadInt32(row, 20)));
                    remoteAddress = ReadIpV6(row, 24, Marshal.ReadInt32(row, 40));
                    remotePort = DecodePort(unchecked((uint)Marshal.ReadInt32(row, 44)));
                    state = Marshal.ReadInt32(row, 48);
                    pid = Marshal.ReadInt32(row, 52);
                }

                yield return new TcpInfo(pid, localAddress, localPort, remoteAddress, remotePort, TcpStateName(state));
            }
        }
        finally
        {
            Marshal.FreeHGlobal(table);
        }
    }

    private static IEnumerable<UdpInfo> ReadUdpFamily(int family)
    {
        var table = ReadTable((IntPtr buffer, ref int size) => GetExtendedUdpTable(
            buffer, ref size, true, family, UdpTableOwnerPid, 0));
        if (table == IntPtr.Zero)
        {
            yield break;
        }

        try
        {
            var count = Marshal.ReadInt32(table);
            var rowSize = family == AfInet ? 12 : 28;
            for (var index = 0; index < count; index++)
            {
                var row = IntPtr.Add(table, sizeof(uint) + (index * rowSize));
                var address = family == AfInet
                    ? new IPAddress(BitConverter.GetBytes(unchecked((uint)Marshal.ReadInt32(row))))
                    : ReadIpV6(row, 0, Marshal.ReadInt32(row, 16));
                var portOffset = family == AfInet ? 4 : 20;
                var pidOffset = family == AfInet ? 8 : 24;
                var port = DecodePort(unchecked((uint)Marshal.ReadInt32(row, portOffset)));
                var pid = Marshal.ReadInt32(row, pidOffset);
                yield return new UdpInfo(pid, address, port);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(table);
        }
    }

    private delegate uint TableReader(IntPtr buffer, ref int size);

    private static IntPtr ReadTable(TableReader read)
    {
        var size = 0;
        var result = read(IntPtr.Zero, ref size);
        if (result != ErrorInsufficientBuffer && result != 0)
        {
            Console.Error.WriteLine($"Network table query failed: {result}");
            return IntPtr.Zero;
        }

        var buffer = Marshal.AllocHGlobal(size);
        result = read(buffer, ref size);
        if (result != 0)
        {
            Marshal.FreeHGlobal(buffer);
            Console.Error.WriteLine($"Network table read failed: {result}");
            return IntPtr.Zero;
        }

        return buffer;
    }

    private static IPAddress ReadIpV6(IntPtr row, int addressOffset, long scopeId)
    {
        var bytes = new byte[16];
        Marshal.Copy(IntPtr.Add(row, addressOffset), bytes, 0, bytes.Length);
        return new IPAddress(bytes, Math.Max(0, scopeId));
    }

    private static int DecodePort(uint rawPort)
    {
        var networkOrder = (ushort)(rawPort & 0xffff);
        return ((networkOrder & 0xff) << 8) | (networkOrder >> 8);
    }

    private static string TcpStateName(int state) => state switch
    {
        1 => "Closed",
        2 => "Listen",
        3 => "SynSent",
        4 => "SynReceived",
        5 => "Established",
        6 => "FinWait1",
        7 => "FinWait2",
        8 => "CloseWait",
        9 => "Closing",
        10 => "LastAck",
        11 => "TimeWait",
        12 => "DeleteTcb",
        _ => $"State{state}"
    };

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32FirstW(IntPtr snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32NextW(IntPtr snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr tcpTable,
        ref int size,
        [MarshalAs(UnmanagedType.Bool)] bool order,
        int addressFamily,
        int tableClass,
        uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(
        IntPtr udpTable,
        ref int size,
        [MarshalAs(UnmanagedType.Bool)] bool order,
        int addressFamily,
        int tableClass,
        uint reserved);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry32
    {
        public uint Size;
        public uint Usage;
        public uint ProcessId;
        public UIntPtr DefaultHeapId;
        public uint ModuleId;
        public uint Threads;
        public uint ParentProcessId;
        public int BasePriority;
        public uint Flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string ExecutableFile;
    }
}

internal sealed record ProcessInfo(int Pid, int ParentPid, string Name);
internal sealed record TcpInfo(int Pid, IPAddress LocalAddress, int LocalPort, IPAddress RemoteAddress, int RemotePort, string State);
internal sealed record UdpInfo(int Pid, IPAddress LocalAddress, int LocalPort);
internal sealed record ProxySettings(bool Enabled, string Server, bool HasPac, bool AutoDetect, int BypassCount, bool IncludesLocal);
