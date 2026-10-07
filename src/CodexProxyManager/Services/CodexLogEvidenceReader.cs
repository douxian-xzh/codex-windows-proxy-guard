using System.IO;

namespace CodexProxyManager.Services;

internal sealed record CodexLogEvidence(
    string SourceFileName,
    DateTimeOffset FileModifiedAt,
    DateTimeOffset ReadAt,
    string ResponsesStatus,
    string RemoteStatus,
    bool TailTruncated,
    int RelevantEventCount,
    string PrivacyNote);

/// <summary>
/// Reads only a user-selected .log/.txt tail, keeps a small allowlist of transport facts,
/// and never returns raw log lines, URLs, request IDs, account data, or conversation text.
/// </summary>
internal static class CodexLogEvidenceReader
{
    private const int MaxTailBytes = 2 * 1024 * 1024;
    private static readonly string[] FallbackMarkers =
    [
        "falling back to http",
        "falling back from websockets to https"
    ];
    private static readonly string[] ResponseFailureMarkers =
    [
        "responses websocket timed out",
        "responses websocket handshake timed out",
        "stream disconnected - retrying sampling request",
        "responses websocket closed (1006)"
    ];

    public static CodexLogEvidence Read(string path)
    {
        var fullPath = Path.GetFullPath(path);
        var extension = Path.GetExtension(fullPath);
        if (!extension.Equals(".log", StringComparison.OrdinalIgnoreCase)
            && !extension.Equals(".txt", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("只读取手动选择的 .log 或 .txt 诊断日志；不读取 JSONL 会话、SQLite、配置或认证文件。");

        var info = new FileInfo(fullPath);
        if (!info.Exists) throw new FileNotFoundException("所选日志不存在。", fullPath);
        if (info.Length == 0) throw new InvalidDataException("所选日志为空。");

        using var stream = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var truncated = stream.Length > MaxTailBytes;
        if (truncated) stream.Seek(-MaxTailBytes, SeekOrigin.End);
        using var reader = new StreamReader(stream, detectEncodingFromByteOrderMarks: true);

        var responsesStatus = "Unknown";
        var remoteStatus = "Unknown";
        var wssAttempt = false;
        var relevantEvents = 0;
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            var text = line.AsSpan();
            var fallbackThisLine = ContainsAny(text, FallbackMarkers);
            var failureThisLine = ContainsAny(text, ResponseFailureMarkers)
                || (wssAttempt && Contains(text, "handshake timed out"));
            if (fallbackThisLine)
            {
                responsesStatus = "FallbackObserved";
                wssAttempt = false;
                relevantEvents++;
            }
            else if (failureThisLine)
            {
                responsesStatus = "WebSocketFailureObserved";
                wssAttempt = false;
                relevantEvents++;
            }

            if (!fallbackThisLine && !failureThisLine && ContainsResponsesWebSocketTransport(text))
            {
                wssAttempt = true;
                responsesStatus = "WebSocketAttemptObserved";
                relevantEvents++;
            }

            if (!fallbackThisLine && !failureThisLine && wssAttempt && ContainsResponseCompletion(text))
            {
                responsesStatus = "WebSocketCompletionObserved";
                wssAttempt = false;
                relevantEvents++;
            }

            if (Contains(text, "hostKind=durable") || Contains(text, "hostkind\":\"durable\""))
            {
                remoteStatus = "DurableRemoteEventObserved";
                relevantEvents++;
            }

            if (Contains(text, "failureReason=open_timeout")
                || Contains(text, "failureReason=\"open_timeout\"")
                || Contains(text, "websocket close code 1006"))
            {
                remoteStatus = "RemoteFailureObserved";
                relevantEvents++;
            }
        }

        return new CodexLogEvidence(
            info.Name,
            info.LastWriteTimeUtc,
            DateTimeOffset.UtcNow,
            responsesStatus,
            remoteStatus,
            truncated,
            relevantEvents,
            "仅读取日志尾部并保留传输状态分类；不导出原始行、URL、请求/会话 ID、账号信息或对话正文。Responses 观察不能单独证明当前授权测试轮；Remote 状态不等于手机端到端通过。");
    }

    private static bool ContainsResponsesWebSocketTransport(ReadOnlySpan<char> text) =>
        Contains(text, "transport=\"responses_websocket\"")
        || Contains(text, "transport=responses_websocket")
        || Contains(text, "\"transport\":\"responses_websocket\"");

    private static bool ContainsResponseCompletion(ReadOnlySpan<char> text) =>
        Contains(text, "turn.completed") || Contains(text, "response.completed");

    private static bool ContainsAny(ReadOnlySpan<char> text, IReadOnlyList<string> markers)
    {
        foreach (var marker in markers)
            if (Contains(text, marker)) return true;
        return false;
    }

    private static bool Contains(ReadOnlySpan<char> text, string value) =>
        text.Contains(value.AsSpan(), StringComparison.OrdinalIgnoreCase);
}
