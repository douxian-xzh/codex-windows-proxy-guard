# Codex Windows Proxy Guardian

**Per-application SOCKS5 proxy protection for the Microsoft Store ChatGPT/Codex app on Windows.** A WPF manager and sign-in Guardian configure the upstream ProxiFyre engine so the original app can be launched normally, while unrelated applications keep their usual network path.

[English](#english) · [简体中文](#简体中文)

## English

### What it does

Codex Windows Proxy Guardian prepares a narrow set of executable-path rules for the installed ChatGPT/Codex package and routes matching traffic through a SOCKS5 endpoint using [Wiresock ProxiFyre](https://github.com/wiresock/proxifyre).

- Discovers the current Microsoft Store/MSIX package and its versioned installation path.
- Tracks confirmed ChatGPT/Codex executable paths, including supported relocated components.
- Checks the configured endpoint with a SOCKS5 protocol handshake.
- Uses a separate sign-in Guardian to prepare and monitor protection; the WPF manager can close without being the app's network launcher.
- Lets you launch the original app from Start, the taskbar, or an existing shortcut. The manager's **Open Codex** button is only a convenience shortcut.
- Provides status, logs, and a user-requested redacted diagnostics export.

### Typical setup

1. Install the **.NET 10 Desktop Runtime x64**.
2. Open the manager and enter the address and port of a SOCKS5-compatible proxy. You can also read the current Windows proxy address into the fields; saving this setting does not change the Windows system proxy.
3. Select **Prepare / Repair Protection**. First-time setup may request administrator approval to install or configure the upstream filtering engine and the sign-in Guardian task.
4. Wait for the manager to report that background protection is ready.
5. Start the original ChatGPT app normally from Windows. The manager does not need to launch it or remain open.

The Guardian and ProxiFyre service must remain healthy for protection to continue. A ready control-plane status is useful operational evidence; it is not by itself proof that a particular cloud connection or feature succeeded.

### Build from source

Requirements: Windows x64 and the **.NET 10 SDK**. The published framework-dependent application requires the .NET 10 Desktop Runtime x64 on its target PC.

From the repository root:

```powershell
dotnet restore src/CodexProxyManager/CodexProxyManager.csproj
dotnet build src/CodexProxyManager/CodexProxyManager.csproj -c Release -r win-x64
dotnet build src/CodexProxyGuardian/CodexProxyGuardian.csproj -c Release -r win-x64
```

The project references pinned ProxiFyre release files under `third_party/`; keep those directory names unchanged. See [docs/BUILD.md](docs/BUILD.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for build and design details. Installable manager binaries are not committed to the source tree; check GitHub Releases if a binary release is published.

### Scope and limitations

- Rules match explicit executable paths. This is not PID isolation: another process using the same executable at the same path may also match.
- Shared tools such as `python.exe`, `node.exe`, `git.exe`, PowerShell, and system services are not added as broad fallback rules.
- This is not a machine-wide VPN, TUN, firewall kill switch, or a guarantee that every brokered/system request is proxied. If the service or filtering driver is unavailable, traffic may not be redirected.
- The application does not set Windows system proxy values, global `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`, DNS, hosts, routes, firewall policy, or TLS validation settings.
- A Guardian **Ready** state reports control-plane checks. It does not prove Responses WebSocket, Remote Control, or another specific end-to-end feature has passed.

The maintainer has reported successful normal use with v1.6 on their own device. Protocol-level Responses WebSocket evidence, phone-side Remote Control end-to-end testing, future Microsoft Store update behavior, and all failure-recovery cases have not been independently verified. See the UI diagnostics and project documents for current status; do not treat a local report as a general compatibility guarantee.

### Licensing

The first-party manager, Guardian, and documentation are licensed under MIT; see the root [`LICENSE`](LICENSE). ProxiFyre is a separate third-party component under **GNU AGPL-3.0-only**; its license, source snapshot, and pinned release metadata are kept under [`third_party/`](third_party/) and described in [`NOTICE.md`](NOTICE.md). The root MIT license does not change the terms for third-party components.

## 简体中文

### 项目用途

Codex Windows Proxy Guardian 是一个 Windows WPF 工具，用于为 Microsoft Store/MSIX 版 ChatGPT/Codex 配置按程序路径匹配的 SOCKS5 代理。后台 Guardian 负责登录后准备与状态检查，实际网络转发由上游 [Wiresock ProxiFyre](https://github.com/wiresock/proxifyre) 完成。

- 自动发现当前 ChatGPT/Codex 安装包及带版本号的安装目录。
- 跟踪已确认的 ChatGPT/Codex 可执行文件路径，并兼容已支持的迁移组件。
- 通过 SOCKS5 协议握手检查代理端点，不以“端口能连接”代替协议验证。
- Guardian 独立于 WPF 界面运行；关闭管理器后，后台保护仍可继续。
- 用户可以从开始菜单、任务栏或原有快捷方式正常启动原版 ChatGPT。管理器的“打开 Codex”只是快捷入口。
- 提供保护状态、日志和用户主动导出的脱敏诊断信息。

### 使用步骤

1. 安装 **.NET 10 Desktop Runtime x64**。
2. 打开管理器，填写支持 SOCKS5 的代理地址和端口；也可以读取 Windows 当前代理地址到输入框。保存此设置不会修改 Windows 系统代理。
3. 点击“准备 / 修复保护”。首次设置可能会请求管理员批准，以安装或配置上游过滤引擎及 Windows 登录后的 Guardian 任务。
4. 等待管理器显示后台保护已就绪。
5. 以后从 Windows 正常启动原版 ChatGPT 即可；不要求通过管理器启动，也不要求管理器一直打开。

后台 Guardian 与 ProxiFyre 服务需要保持健康，代理保护才能持续工作。“已就绪”表示控制面检查通过，并不单独证明某个云端连接或功能已完成端到端验收。

### 从源码构建

需要 Windows x64 和 **.NET 10 SDK**。依赖框架的发布程序需要目标电脑安装 .NET 10 Desktop Runtime x64。

在仓库根目录运行：

```powershell
dotnet restore src/CodexProxyManager/CodexProxyManager.csproj
dotnet build src/CodexProxyManager/CodexProxyManager.csproj -c Release -r win-x64
dotnet build src/CodexProxyGuardian/CodexProxyGuardian.csproj -c Release -r win-x64
```

工程引用 `third_party/` 中固定版本的 ProxiFyre 发布文件，请保持原目录名不变。更多信息见[构建说明](docs/BUILD.md)和[架构与限制](docs/ARCHITECTURE.md)。源码仓库不提交管理器安装包；如有可下载版本，请查看 GitHub Releases。

### 代理范围与限制

- 规则按明确的可执行文件路径匹配，不是 PID 隔离；同一路径下运行的其他同名程序也可能匹配。
- 不会把 `python.exe`、`node.exe`、`git.exe`、PowerShell 或系统服务加入宽泛兜底规则。
- 本项目不是整机 VPN、TUN、防火墙 Kill Switch，也不保证所有 Windows broker/system 请求都会被代理。过滤驱动或服务不可用时，流量可能无法转发。
- 不设置 Windows 系统代理、全局 `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`、DNS、hosts、路由、防火墙策略或 TLS 校验配置。
- Guardian 显示“已就绪”仅代表控制面检查通过，不能据此宣称 Responses WebSocket、Remote Control 或其他具体端到端功能已通过。

维护者报告 v1.6 在本人设备上的日常使用成功。Responses WebSocket 协议级证据、手机端 Remote Control 端到端测试、未来 Microsoft Store 更新行为及全部故障恢复场景尚未独立验证。请查看界面诊断与项目文档了解当前状态，不要将单机反馈理解为普遍兼容保证。

### 许可证

本项目原创管理器、Guardian 和文档使用 MIT 许可证，见根目录 [`LICENSE`](LICENSE)。ProxiFyre 是单独的第三方组件，使用 **GNU AGPL-3.0-only**；其许可证、源码快照和固定版本元数据位于 [`third_party/`](third_party/)，详情见 [`NOTICE.md`](NOTICE.md)。根目录 MIT 许可证不会改变第三方组件的许可条款。
