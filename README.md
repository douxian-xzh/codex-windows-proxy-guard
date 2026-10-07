# Codex Windows Proxy Guardian

面向中国大陆 Windows 用户的 ChatGPT/Codex 代理修复工具。用于解决新对话反复重连五次后才回退成功、Remote Control 远程控制二维码无法加载等代理连接问题。

程序通过 [Wiresock ProxiFyre](https://github.com/wiresock/proxifyre)，将 ChatGPT/Codex 的网络连接单独转发到 SOCKS5 代理。它不修改 Windows 系统代理，不设置全局代理环境变量，也不把其他应用加入代理规则。维护者已在本机验证 v1.6：新对话无需重连五次，远程控制二维码正常加载。不同网络和客户端版本的效果可能不同。

## 怎么使用

1. 安装 **.NET 10 Desktop Runtime x64**。
2. 打开管理器，填写 SOCKS5 代理地址和端口，点击“准备 / 修复保护”。首次设置可能需要管理员确认。
3. 显示后台保护已就绪后，照常从开始菜单、任务栏或桌面快捷方式启动 ChatGPT/Codex。之后不需要先打开管理器。

后台 Guardian 和 ProxiFyre 服务需要保持运行。管理器可以关闭；“打开 Codex”按钮只是快捷入口。

## 工作方式与范围

- 自动发现 Microsoft Store / MSIX 版 ChatGPT/Codex 的当前安装路径，适配带版本号的目录变化。
- 按已确认的程序文件路径匹配流量，由 ProxiFyre 转发至配置的 SOCKS5 端点。
- 只为 ChatGPT/Codex 配置规则，不启用整机 TUN，不修改系统代理、全局 `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY`、DNS、hosts、路由或防火墙设置。
- 规则按程序路径匹配，不是 PID 隔离；共享程序和系统服务不会被作为通用兜底规则加入。
- Guardian 显示“已就绪”表示后台检查通过，不代表每项云端功能都已端到端验证。代理服务或过滤驱动异常时，目标流量可能无法正常转发。

## 从源码构建

需要 Windows x64 和 **.NET 10 SDK**。在仓库根目录运行：

```powershell
dotnet restore src/CodexProxyManager/CodexProxyManager.csproj
dotnet build src/CodexProxyManager/CodexProxyManager.csproj -c Release -r win-x64
dotnet build src/CodexProxyGuardian/CodexProxyGuardian.csproj -c Release -r win-x64
```

源码仓库不包含管理器安装包。如有可下载版本，请查看 GitHub Releases。构建细节见 [构建说明](docs/BUILD.md)，设计说明见 [架构文档](docs/ARCHITECTURE.md)。

## 许可证

本项目原创管理器、Guardian 和文档使用 MIT 许可证，见 [`LICENSE`](LICENSE)。第三方 ProxiFyre 使用 **GNU AGPL-3.0-only**；相关许可证与版本信息见 [`NOTICE.md`](NOTICE.md) 和 [`third_party/`](third_party/)。

## English

Codex Windows Proxy Guardian is a Windows tool for ChatGPT/Codex users whose proxy setup causes new chats to reconnect five times before falling back, or prevents the Remote Control QR code from loading. It routes matching ChatGPT/Codex traffic through a SOCKS5 proxy with [Wiresock ProxiFyre](https://github.com/wiresock/proxifyre), while leaving Windows system proxy settings and other apps' routing unchanged.

The maintainer verified v1.6 on their own PC: new chats started without the five-retry fallback and the Remote Control QR code loaded. Results may vary by network and client version.

Install the .NET 10 Desktop Runtime x64, enter a SOCKS5 endpoint, and select **Prepare / Repair Protection**. After protection is ready, launch the original ChatGPT/Codex normally from Windows. The manager can close; the sign-in Guardian and ProxiFyre service must remain healthy. See [build instructions](docs/BUILD.md), [architecture](docs/ARCHITECTURE.md), and [license notices](NOTICE.md).
