using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CodexProxyManager.Services;

/// <summary>Identifies only this Store package's relocated copies, using its immutable resource descriptors.</summary>
internal static class RelocatedBackendDiscovery
{
    private static readonly string[] DescriptorNames =
        ["codex.exe", "codex-code-mode-host.exe", "codex-windows-sandbox-setup.exe", "codex-command-runner.exe"];
    private static readonly string[] NetworkNames = ["codex.exe", "codex-command-runner.exe"];
    private static readonly ConcurrentDictionary<string, SourceIdentity> Identities = new(StringComparer.OrdinalIgnoreCase);

    internal static TargetApplication Attach(TargetApplication target)
    {
        var originalPaths = target.RuleExecutablePaths.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var bundledCodex = Path.Combine(target.InstallLocation, "app", "resources", "codex.exe");
        if (!originalPaths.Contains(bundledCodex)) return target;
        var identity = ReadSourceIdentity(target.InstallLocation);
        var components = target.KnownComponents.ToList();
        var paths = target.RuleExecutablePaths.ToList();
        foreach (var name in NetworkNames)
        {
            if (!originalPaths.Contains(Path.Combine(target.InstallLocation, "app", "resources", name))) continue;
            var expected = ExpectedPath(identity, name);
            VerifyDestination(expected, identity, name);
            var materialized = File.Exists(expected);
            paths.Add(expected);
            components.Add(new TargetExecutableComponent(
                "运行缓存/" + identity.CacheKey + "/" + name, expected,
                materialized ? "已核验的客户端后台缓存副本" : "当前客户端后台的确定性缓存路径（待客户端生成）", true,
                "缓存目录由当前 Store 包四个资源文件的描述指纹确定；已存在文件须与包内原件 SHA-256 一致。" +
                "规则只包含此具体 EXE；同路径所有实例会匹配，不是 PID 隔离。"));
        }
        return target with
        {
            RuleExecutablePaths = paths.Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(path => path, StringComparer.OrdinalIgnoreCase).ToArray(),
            Components = components
        };
    }

    internal static void VerifyExpectedRulePath(string installLocation, string path)
    {
        var identity = ReadSourceIdentity(installLocation);
        var name = NetworkNames.FirstOrDefault(candidate => string.Equals(
            Path.GetFullPath(path), ExpectedPath(identity, candidate), StringComparison.OrdinalIgnoreCase));
        if (name is null)
            throw new InvalidDataException("包外执行文件不是当前客户端的确定性后台缓存路径，拒绝加入代理规则。");
        VerifyDestination(path, identity, name);
    }

    private static SourceIdentity ReadSourceIdentity(string installLocation)
    {
        var root = Path.GetFullPath(installLocation).TrimEnd(Path.DirectorySeparatorChar);
        var windowsApps = Path.GetFullPath(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WindowsApps"));
        var packageName = Path.GetFileName(root);
        if (!string.Equals(Path.GetDirectoryName(root), windowsApps, StringComparison.OrdinalIgnoreCase)
            || !packageName.StartsWith("OpenAI.Codex_", StringComparison.OrdinalIgnoreCase)
            || !packageName.EndsWith("_2p2nqsd0c76g0", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("后台缓存身份只从受保护的 OpenAI.Codex Store 包派生。");
        var resources = Path.Combine(root, "app", "resources");
        var before = DescriptorNames.Select(name => ReadStamp(Path.Combine(resources, name), root)).ToArray();
        if (Identities.TryGetValue(root, out var cached) && cached.Stamps.SequenceEqual(before)) return cached;
        using var descriptorHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var hashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in DescriptorNames)
        {
            var hash = ComputeHash(Path.Combine(resources, name)).ToLowerInvariant();
            hashes.Add(name, hash);
            descriptorHash.AppendData(Encoding.UTF8.GetBytes(name + "\0" + hash + "\0"));
        }
        if (!before.SequenceEqual(DescriptorNames.Select(name => ReadStamp(Path.Combine(resources, name), root))))
            throw new IOException("核验过程中客户端包资源发生变化，请重新发现安装。");
        var key = Convert.ToHexString(descriptorHash.GetHashAndReset()).ToLowerInvariant()[..16];
        var result = new SourceIdentity(key, hashes, before);
        if (Identities.Count >= 8) Identities.Clear();
        Identities[root] = result;
        return result;
    }

    private static string ExpectedPath(SourceIdentity identity, string name) => Path.GetFullPath(Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "OpenAI", "Codex", "bin", identity.CacheKey, name));

    private static void VerifyDestination(string path, SourceIdentity identity, string name)
    {
        var localRoot = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        CheckDirectoryChain(Path.GetDirectoryName(path)!, localRoot);
        FileAttributes attributes;
        try { attributes = File.GetAttributes(path); }
        catch (FileNotFoundException) { return; } // The precise expected rule can be prepared before first launch.
        catch (DirectoryNotFoundException) { return; }
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0
            || !string.Equals(ComputeHash(path), identity.Hashes[name], StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("客户端后台缓存文件与包内原件不一致或为重解析点；拒绝代理未知副本，请导出诊断。");
    }

    private static FileStamp ReadStamp(string path, string root)
    {
        CheckDirectoryChain(Path.GetDirectoryName(path)!, root);
        var info = new FileInfo(path);
        if (!info.Exists || info.Length == 0 || (info.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
            throw new InvalidDataException("客户端后台资源文件缺失或不是普通文件，无法确认缓存身份。");
        return new FileStamp(info.Length, info.LastWriteTimeUtc.Ticks, info.CreationTimeUtc.Ticks);
    }

    private static void CheckDirectoryChain(string directory, string root)
    {
        var fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar);
        var cursor = Path.GetFullPath(directory).TrimEnd(Path.DirectorySeparatorChar);
        if (cursor != fullRoot && !cursor.StartsWith(fullRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("后台文件路径超出固定目录。");
        while (true)
        {
            try
            {
                var attributes = File.GetAttributes(cursor);
                if ((attributes & FileAttributes.Directory) == 0 || (attributes & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidDataException("后台资源或缓存目录为重解析点，拒绝使用。");
            }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }
            if (string.Equals(cursor, fullRoot, StringComparison.OrdinalIgnoreCase)) break;
            cursor = Path.GetDirectoryName(cursor) ?? throw new InvalidDataException("后台目录无效。");
        }
    }

    private static string ComputeHash(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private sealed record FileStamp(long Length, long ModifiedTicks, long CreatedTicks);
    private sealed record SourceIdentity(string CacheKey, IReadOnlyDictionary<string, string> Hashes, FileStamp[] Stamps);
}
