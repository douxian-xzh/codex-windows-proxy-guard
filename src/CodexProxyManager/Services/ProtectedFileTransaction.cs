using System.IO;
using System.Security.Cryptography;

namespace CodexProxyManager.Services;

internal sealed record ProtectedFileSnapshot(
    string TargetPath,
    string? BackupPath,
    string CandidateSha256,
    string? OriginalSha256);

/// <summary>Verifies payload bytes before elevation-bound replacement and restores only unchanged candidates.</summary>
internal static class ProtectedFileTransaction
{
    public static byte[] ReadVerifiedPayload(string path, string expectedSha256, string label)
    {
        var attributes = File.GetAttributes(path);
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
            throw new InvalidDataException($"随包{label}不是普通文件，拒绝提权使用。");

        var bytes = File.ReadAllBytes(path);
        var actualHash = Convert.ToHexString(SHA256.HashData(bytes));
        if (!string.Equals(actualHash, expectedSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException($"随包{label}校验失败，拒绝以管理员权限运行。文件：{Path.GetFileName(path)}");
        return bytes;
    }

    public static ProtectedFileSnapshot Replace(string targetPath, byte[] candidateBytes, string backupDirectory)
    {
        targetPath = Path.GetFullPath(targetPath);
        var directory = Path.GetDirectoryName(targetPath) ?? throw new InvalidOperationException("目标文件路径无效。");
        Directory.CreateDirectory(directory);

        string? backupPath = null;
        string? originalHash = null;
        if (File.Exists(targetPath))
        {
            var attributes = File.GetAttributes(targetPath);
            if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
                throw new InvalidDataException($"受保护文件不是普通文件，拒绝替换：{Path.GetFileName(targetPath)}");

            var originalBytes = File.ReadAllBytes(targetPath);
            originalHash = Convert.ToHexString(SHA256.HashData(originalBytes));
            Directory.CreateDirectory(backupDirectory);
            backupPath = Path.Combine(Path.GetFullPath(backupDirectory), Path.GetFileName(targetPath) + ".previous");
            AtomicWrite(backupPath, originalBytes);
        }

        var candidateHash = Convert.ToHexString(SHA256.HashData(candidateBytes));
        AtomicWrite(targetPath, candidateBytes);
        return new ProtectedFileSnapshot(targetPath, backupPath, candidateHash, originalHash);
    }

    public static void Restore(ProtectedFileSnapshot snapshot)
    {
        if (!File.Exists(snapshot.TargetPath)
            || !string.Equals(ComputeHash(snapshot.TargetPath), snapshot.CandidateSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"{Path.GetFileName(snapshot.TargetPath)} 已变化；为保护外部修改，拒绝自动恢复。");

        if (snapshot.BackupPath is null)
        {
            File.Delete(snapshot.TargetPath);
            return;
        }

        if (snapshot.OriginalSha256 is null || !File.Exists(snapshot.BackupPath)
            || !string.Equals(ComputeHash(snapshot.BackupPath), snapshot.OriginalSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException($"{Path.GetFileName(snapshot.TargetPath)} 的受保护备份缺失或校验失败。");

        AtomicWrite(snapshot.TargetPath, File.ReadAllBytes(snapshot.BackupPath));
    }

    public static string ComputeHash(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    public static void AtomicWrite(string path, byte[] bytes)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path)) ?? throw new InvalidOperationException("目标目录无效。");
        Directory.CreateDirectory(directory);
        var temporaryPath = Path.Combine(directory, "." + Path.GetFileName(path) + "." + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var stream = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, FileOptions.WriteThrough))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporaryPath, path, overwrite: true);
        }
        finally
        {
            try { File.Delete(temporaryPath); } catch { }
        }
    }
}
