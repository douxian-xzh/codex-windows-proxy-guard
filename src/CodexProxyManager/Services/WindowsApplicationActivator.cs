using System.Runtime.InteropServices;
using System.IO;

namespace CodexProxyManager.Services;

/// <summary>
/// Activates a packaged Windows application through the same AUMID entry point
/// used by Start and other normal Windows application launch surfaces.
/// </summary>
public static class WindowsApplicationActivator
{
    public static int Activate(TargetApplication target)
    {
        var appUserModelId = GetValidatedAppUserModelId(target);
        IApplicationActivationManager? activationManager = null;
        try
        {
            activationManager = (IApplicationActivationManager)new ApplicationActivationManager();
            var result = activationManager.ActivateApplication(appUserModelId, null, 0, out var processId);
            Marshal.ThrowExceptionForHR(result);
            if (processId == 0)
                throw new InvalidOperationException("Windows 已接受应用激活请求，但没有返回进程 ID。");

            return checked((int)processId);
        }
        finally
        {
            if (activationManager is not null && Marshal.IsComObject(activationManager))
                Marshal.FinalReleaseComObject(activationManager);
        }
    }

    internal static string GetValidatedAppUserModelId(TargetApplication target)
    {
        ArgumentNullException.ThrowIfNull(target);
        if (string.IsNullOrWhiteSpace(target.PackageFamilyName)
            || string.IsNullOrWhiteSpace(target.ApplicationId)
            || string.IsNullOrWhiteSpace(target.AppUserModelId))
            throw new InvalidDataException("目标应用缺少有效的 MSIX 包族名、应用 ID 或 AUMID。");

        var expected = target.PackageFamilyName + "!" + target.ApplicationId;
        if (!string.Equals(target.AppUserModelId, expected, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("目标应用的 AUMID 与已发现的包族名/应用 ID 不一致。");

        return expected;
    }

    [ComImport]
    [Guid("45BA127D-10A8-46EA-8AB7-56EA9078943C")]
    [ClassInterface(ClassInterfaceType.None)]
    private class ApplicationActivationManager { }

    [ComImport]
    [Guid("2E941141-7F97-4756-BA1D-9DECDE894A3D")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IApplicationActivationManager
    {
        [PreserveSig]
        int ActivateApplication(
            [MarshalAs(UnmanagedType.LPWStr)] string appUserModelId,
            [MarshalAs(UnmanagedType.LPWStr)] string? arguments,
            uint options,
            out uint processId);
    }
}
