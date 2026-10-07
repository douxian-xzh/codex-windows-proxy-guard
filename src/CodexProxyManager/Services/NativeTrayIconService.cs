using System.Runtime.InteropServices;
using System.IO;
using System.Windows.Interop;

namespace CodexProxyManager.Services;

/// <summary>Creates a notification area icon and native popup menu without Windows Forms.</summary>
public sealed class NativeTrayIconService : IDisposable
{
    private const uint NotifyMessage = 0x8000 + 0x42;
    private const uint NimAdd = 0;
    private const uint NimDelete = 2;
    private const uint NifMessage = 0x1;
    private const uint NifIcon = 0x2;
    private const uint NifTip = 0x4;
    private const uint WmLButtonDoubleClick = 0x0203;
    private const uint WmRButtonUp = 0x0205;
    private const uint WmContextMenu = 0x007B;
    private const uint WmNull = 0;
    private static readonly uint TaskbarCreatedMessage = RegisterWindowMessage("TaskbarCreated");
    private const uint MfString = 0x0000;
    private const uint MfSeparator = 0x0800;
    private const uint TpmRightButton = 0x0002;
    private const uint TpmReturnCommand = 0x0100;
    private const uint ImageIcon = 1;
    private const uint LrDefaultSize = 0x40;
    private const uint LrLoadFromFile = 0x10;

    private const uint OpenCommand = 1001;
    private const uint StartCommand = 1002;
    private const uint StopCommand = 1003;
    private const uint ExitCommand = 1004;

    private readonly HwndSource _messageWindow;
    private readonly IntPtr _iconHandle;
    private readonly Func<IntPtr> _ownerHandle;
    private readonly Action _open;
    private readonly Action _start;
    private readonly Action _stop;
    private readonly Action _exit;
    private bool _visible = true;
    private bool _disposed;

    public bool Visible
    {
        get => _visible;
        set
        {
            if (_disposed || _visible == value) return;
            _visible = value;
            if (value) AddIcon();
            else RemoveIcon();
        }
    }

    public NativeTrayIconService(
        byte[] iconFile,
        string tooltip,
        Func<IntPtr> ownerHandle,
        Action open,
        Action start,
        Action stop,
        Action exit)
    {
        _open = open;
        _ownerHandle = ownerHandle;
        _start = start;
        _stop = stop;
        _exit = exit;

        var parameters = new HwndSourceParameters("CodexProxyManager.TrayMessageWindow")
        {
            ParentWindow = new IntPtr(-3), // HWND_MESSAGE
            Width = 0,
            Height = 0,
            WindowStyle = 0
        };
        _messageWindow = new HwndSource(parameters);
        _messageWindow.AddHook(WindowProc);

        try
        {
            _iconHandle = CreateIcon(iconFile);
            if (_iconHandle == IntPtr.Zero)
                throw new InvalidOperationException("无法从托盘图标资源创建 Windows 图标。");

            Tooltip = tooltip;
            AddIcon();
        }
        catch
        {
            if (_iconHandle != IntPtr.Zero) _ = DestroyIcon(_iconHandle);
            _messageWindow.RemoveHook(WindowProc);
            _messageWindow.Dispose();
            throw;
        }
    }

    private string Tooltip { get; }

    private static IntPtr CreateIcon(byte[] file)
    {
        var iconPath = Path.Combine(Path.GetTempPath(), $"CodexProxyManager-{Guid.NewGuid():N}-Tray.ico");
        try
        {
            File.WriteAllBytes(iconPath, file);
            var icon = LoadImage(IntPtr.Zero, iconPath, ImageIcon, 0, 0, LrLoadFromFile | LrDefaultSize);
            if (icon == IntPtr.Zero)
                throw new InvalidOperationException($"Windows 无法读取托盘图标（错误 {Marshal.GetLastWin32Error()}）。");
            return icon;
        }
        finally
        {
            try { File.Delete(iconPath); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    private void AddIcon()
    {
        var data = CreateData();
        if (!Shell_NotifyIcon(NimAdd, ref data))
            throw new InvalidOperationException($"Windows 未能创建托盘图标（错误 {Marshal.GetLastWin32Error()}）。");
    }

    private void RemoveIcon()
    {
        var data = CreateData();
        _ = Shell_NotifyIcon(NimDelete, ref data);
    }

    private NOTIFYICONDATA CreateData() => new()
    {
        cbSize = (uint)Marshal.SizeOf<NOTIFYICONDATA>(),
        hWnd = _messageWindow.Handle,
        uID = 1,
        uFlags = NifMessage | NifIcon | NifTip,
        uCallbackMessage = NotifyMessage,
        hIcon = _iconHandle,
        szTip = Tooltip.Length > 127 ? Tooltip[..127] : Tooltip,
        szInfo = string.Empty,
        szInfoTitle = string.Empty,
        guidItem = Guid.Empty
    };

    private IntPtr WindowProc(IntPtr hwnd, int message, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if ((uint)message == TaskbarCreatedMessage && _visible && !_disposed)
        {
            AddIcon();
            handled = true;
        }
        else if ((uint)message == NotifyMessage)
        {
            var trayEvent = unchecked((uint)lParam.ToInt64());
            if (trayEvent == WmLButtonDoubleClick)
            {
                _open();
                handled = true;
            }
            else if (trayEvent is WmRButtonUp or WmContextMenu)
            {
                ShowContextMenu();
                handled = true;
            }
        }

        return IntPtr.Zero;
    }

    private void ShowContextMenu()
    {
        var menu = CreatePopupMenu();
        if (menu == IntPtr.Zero) return;

        try
        {
            _ = AppendMenu(menu, MfString, new IntPtr(OpenCommand), "打开管理器");
            _ = AppendMenu(menu, MfString, new IntPtr(StartCommand), "启动 ChatGPT / Codex");
            _ = AppendMenu(menu, MfString, new IntPtr(StopCommand), "关闭 ChatGPT");
            _ = AppendMenu(menu, MfSeparator, IntPtr.Zero, null);
            _ = AppendMenu(menu, MfString, new IntPtr(ExitCommand), "退出管理器");

            var owner = _ownerHandle();
            if (owner == IntPtr.Zero) return;
            _ = SetForegroundWindow(owner);
            _ = GetCursorPos(out var position);
            var command = TrackPopupMenu(menu, TpmRightButton | TpmReturnCommand,
                position.X, position.Y, 0, owner, IntPtr.Zero);
            _ = PostMessage(owner, WmNull, IntPtr.Zero, IntPtr.Zero);

            switch (command)
            {
                case OpenCommand: _open(); break;
                case StartCommand: _start(); break;
                case StopCommand: _stop(); break;
                case ExitCommand: _exit(); break;
            }
        }
        finally
        {
            _ = DestroyMenu(menu);
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_visible) RemoveIcon();
        _messageWindow.RemoveHook(WindowProc);
        _messageWindow.Dispose();
        _ = DestroyIcon(_iconHandle);
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NOTIFYICONDATA
    {
        public uint cbSize;
        public IntPtr hWnd;
        public uint uID;
        public uint uFlags;
        public uint uCallbackMessage;
        public IntPtr hIcon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string szTip;
        public uint dwState;
        public uint dwStateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string szInfo;
        public uint uTimeout;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string szInfoTitle;
        public uint dwInfoFlags;
        public Guid guidItem;
        public IntPtr hBalloonIcon;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT { public int X; public int Y; }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Shell_NotifyIcon(uint message, ref NOTIFYICONDATA data);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr LoadImage(IntPtr instance, string name, uint type, int width, int height, uint flags);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyIcon(IntPtr icon);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr CreatePopupMenu();

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AppendMenu(IntPtr menu, uint flags, IntPtr idOrSubmenu, string? text);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyMenu(IntPtr menu);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetForegroundWindow(IntPtr window);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetCursorPos(out POINT point);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint TrackPopupMenu(IntPtr menu, uint flags, int x, int y, int reserved, IntPtr owner, IntPtr rect);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PostMessage(IntPtr window, uint message, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern uint RegisterWindowMessage(string message);
}
