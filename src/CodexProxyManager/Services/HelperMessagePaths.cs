using System.IO;

namespace CodexProxyManager.Services;

/// <summary>Both ends of a helper exchange use the complete request suffix, not just .json.</summary>
internal static class HelperMessagePaths
{
    internal static string ResponseFor(string requestPath, string responseSuffix)
    {
        const string requestSuffix = ".request.json";
        if (!requestPath.EndsWith(requestSuffix, StringComparison.OrdinalIgnoreCase)
            || responseSuffix is not (".result.json" or ".response.json"))
            throw new InvalidDataException("辅助程序消息文件名无效。");
        return requestPath[..^requestSuffix.Length] + responseSuffix;
    }
}
