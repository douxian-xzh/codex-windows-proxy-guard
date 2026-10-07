using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;

namespace CodexProxyManager.Services;

public sealed record NativeProcessInfo(int ProcessId, int ParentProcessId, string Name);
public sealed record TcpConnectionInfo(
    int ProcessId,
    IPAddress LocalAddress,
    int LocalPort,
    IPAddress RemoteAddress,
    int RemotePort,
    string State);
public sealed record UdpEndpointInfo(int ProcessId, IPAddress LocalAddress, int LocalPort);

public static class WindowsNativeSnapshot
{
    private const int ErrorInsufficientBuffer = 122;
    private const int ErrorAppModelNoPackage = 15700;
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int TcpTableOwnerPidAll = 5;
    private const int UdpTableOwnerPid = 1;
    private const uint Th32csSnapProcess = 0x00000002;
    private const uint ProcessQueryLimitedInformation = 0x1000;

    public static IReadOnlyDictionary<int, NativeProcessInfo> ReadProcesses()
    {
        var snapshot = CreateToolhelp32Snapshot(Th32csSnapProcess, 0);
        if (snapshot == IntPtr.Zero || snapshot == new IntPtr(-1))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        try
        {
            var entry = new ProcessEntry32 { Size = (uint)Marshal.SizeOf<ProcessEntry32>() };
            var result = new Dictionary<int, NativeProcessInfo>();
            if (!Process32FirstW(snapshot, ref entry))
            {
                return result;
            }

            do
            {
                var pid = (int)entry.ProcessId;
                result[pid] = new NativeProcessInfo(pid, (int)entry.ParentProcessId, entry.ExecutableFile);
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

    public static string? ReadImagePath(int processId)
    {
        var process = OpenProcess(ProcessQueryLimitedInformation, false, (uint)processId);
        if (process == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            var capacity = 32768;
            var buffer = new System.Text.StringBuilder(capacity);
            return QueryFullProcessImageNameW(process, 0, buffer, ref capacity) ? buffer.ToString() : null;
        }
        finally
        {
            CloseHandle(process);
        }
    }

    public static string? ReadPackageFamilyName(int processId)
    {
        var process = OpenProcess(ProcessQueryLimitedInformation, false, (uint)processId);
        if (process == IntPtr.Zero)
            return null;

        try
        {
            uint familyLength = 0;
            var result = GetPackageFamilyName(process, ref familyLength, null);
            if (result == ErrorAppModelNoPackage || result != ErrorInsufficientBuffer || familyLength is < 2 or > 512)
                return null;

            var familyName = new System.Text.StringBuilder(checked((int)familyLength));
            result = GetPackageFamilyName(process, ref familyLength, familyName);
            return result == 0 && familyName.Length > 0 ? familyName.ToString() : null;
        }
        finally
        {
            CloseHandle(process);
        }
    }

    public static IReadOnlyList<TcpConnectionInfo> ReadTcpConnections()
    {
        var rows = new List<TcpConnectionInfo>();
        rows.AddRange(ReadTcpFamily(AfInet));
        rows.AddRange(ReadTcpFamily(AfInet6));
        return rows;
    }

    public static IReadOnlyList<UdpEndpointInfo> ReadUdpEndpoints()
    {
        var rows = new List<UdpEndpointInfo>();
        rows.AddRange(ReadUdpFamily(AfInet));
        rows.AddRange(ReadUdpFamily(AfInet6));
        return rows;
    }

    private static IEnumerable<TcpConnectionInfo> ReadTcpFamily(int family)
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
                int processId;

                if (family == AfInet)
                {
                    localAddress = new IPAddress(BitConverter.GetBytes(unchecked((uint)Marshal.ReadInt32(row, 4))));
                    localPort = DecodePort(unchecked((uint)Marshal.ReadInt32(row, 8)));
                    remoteAddress = new IPAddress(BitConverter.GetBytes(unchecked((uint)Marshal.ReadInt32(row, 12))));
                    remotePort = DecodePort(unchecked((uint)Marshal.ReadInt32(row, 16)));
                    processId = Marshal.ReadInt32(row, 20);
                }
                else
                {
                    localAddress = ReadIpV6(row, 0, Marshal.ReadInt32(row, 16));
                    localPort = DecodePort(unchecked((uint)Marshal.ReadInt32(row, 20)));
                    remoteAddress = ReadIpV6(row, 24, Marshal.ReadInt32(row, 40));
                    remotePort = DecodePort(unchecked((uint)Marshal.ReadInt32(row, 44)));
                    state = Marshal.ReadInt32(row, 48);
                    processId = Marshal.ReadInt32(row, 52);
                }

                yield return new TcpConnectionInfo(
                    processId, localAddress, localPort, remoteAddress, remotePort, TcpStateName(state));
            }
        }
        finally
        {
            Marshal.FreeHGlobal(table);
        }
    }

    private static IEnumerable<UdpEndpointInfo> ReadUdpFamily(int family)
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
                var processId = Marshal.ReadInt32(row, pidOffset);
                yield return new UdpEndpointInfo(processId, address, port);
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
            throw new Win32Exception((int)result, "读取 Windows 网络连接表失败。");
        }

        if (size <= 0)
        {
            return IntPtr.Zero;
        }

        var buffer = Marshal.AllocHGlobal(size);
        result = read(buffer, ref size);
        if (result != 0)
        {
            Marshal.FreeHGlobal(buffer);
            throw new Win32Exception((int)result, "读取 Windows 网络连接表失败。");
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
        1 => "关闭",
        2 => "监听",
        3 => "连接中",
        4 => "已收到连接",
        5 => "已建立",
        6 => "等待关闭",
        7 => "等待关闭",
        8 => "对端已关闭",
        9 => "正在关闭",
        10 => "最后确认",
        11 => "等待删除",
        12 => "删除中",
        _ => $"状态 {state}"
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
    private static extern IntPtr OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageNameW(IntPtr process, uint flags, System.Text.StringBuilder imageName, ref int size);

    [DllImport("kernel32.dll", EntryPoint = "GetPackageFamilyName", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int GetPackageFamilyName(IntPtr process, ref uint packageFamilyNameLength, System.Text.StringBuilder? packageFamilyName);

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
