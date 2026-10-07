namespace CodexProxyManager.Services;

// User-facing summary only. Network acceptance remains a separate, evidence-based result.
public sealed record ProtectionPresentation(string Title, string NextAction, string Tone)
{
    public static ProtectionPresentation From(GuardianStatusView guardian, bool loginEnabled)
    {
        if (!guardian.IsLive)
            return new("后台保护尚未确认", loginEnabled
                ? "登录任务已启用，但尚未收到运行中的后台状态。可取消后重新勾选以启动后台；仍异常请导出诊断。"
                : "先准备保护，再启用“Windows 登录后自动准备保护”。已有后台时，可重新检测或导出诊断。", "Warning");

        return guardian.State switch
        {
            "Ready" => new("后台保护已就绪", loginEnabled
                ? "可从开始菜单或任务栏正常打开 Codex。客户端连接验证见高级诊断。"
                : "可正常打开 Codex；建议启用登录后自动准备，以便下次登录继续使用。", "Ready"),
            "Initializing" => new("正在准备保护", "后台正在检查应用与连接，请稍候；无需反复打开 Codex。", "Neutral"),
            "ProxyUnavailable" => new("代理连接不可用", "展开连接设置，确认代理地址与端口，再点击“检测代理”。", "Warning"),
            "EngineUnavailable" => new("保护组件未就绪", "点击“准备 / 修复保护”检查并配置组件；首次配置需要管理员授权。", "Warning"),
            "ConfigInvalid" => new("保护配置需要检查", "点击“准备 / 修复保护”；详细原因与配置状态见高级诊断。", "Warning"),
            "CodexNotInstalled" => new("未发现 Codex", "请先安装原版 Codex / ChatGPT，然后点击“重新检测”。", "Warning"),
            "NeedsRepair" => new("保护需要修复", "点击“准备 / 修复保护”；若仍异常，请导出诊断。", "Warning"),
            _ => new("保护状态待确认", "点击“重新检测”；若状态持续异常，请导出诊断。", "Warning")
        };
    }
}
