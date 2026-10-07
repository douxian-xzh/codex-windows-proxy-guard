# Codex Windows Proxy Guardian

**A Windows per-app SOCKS5 proxy manager for ChatGPT and Codex.** WPF manager + background Guardian + the upstream ProxiFyre 2.6.1 engine. Keep your normal Windows networking for other applications.

**Codex 代理管理器** 是面向 Windows 的 ChatGPT/Codex 按程序透明代理工具：后台 Guardian 负责路径发现和保护状态，ProxiFyre 将已确认的 ChatGPT/Codex 网络流量转给 SOCKS5。其他程序不加入 Codex 规则，也不要求用户从管理器启动 ChatGPT。

## What it does

- Discovers the current Microsoft Store/MSIX ChatGPT package and its versioned install path.
- Tracks confirmed bundled `ChatGPT.exe`, `codex.exe` and command-runner paths as the package changes.
- Prepares protection after Windows sign-in with a separate Guardian task; the manager UI may close.
- Uses ProxiFyre 2.6.1 for per-application TCP/UDP redirection to a verified SOCKS5 endpoint.
- Provides a Chinese WPF interface, tray status, endpoint checks and redacted diagnostics.
- Does not set global proxy environment variables, Windows system proxy, DNS, hosts or a whole-machine TUN.

## Important limits

This is a path based application rule, not PID isolation and not a machine-wide VPN or kill switch. Shared executables are not added as catch-all rules. Some brokered/system traffic and unsupported engine traffic may fall outside the application rule. If ProxiFyre or its driver is unavailable, this app does not claim a permanent “proxy or block” guarantee.

A **Ready** Guardian status means the control plane confirmed its current protection snapshot. It does not by itself prove a particular Responses WebSocket or Remote Control session succeeded. See [architecture and limits](docs/ARCHITECTURE.md).

## Licensing

The first-party manager, Guardian and documentation in this repository are MIT licensed. The separately distributed ProxiFyre 2.6.1 component remains **AGPL-3.0-only** under its upstream license; its license, source snapshot and pinned release metadata are included under `third_party/`. See [NOTICE.md](NOTICE.md). Do not interpret the repository's MIT license as relicensing third-party files.

## Build

Use Windows x64 with .NET 10 SDK. The published app is framework dependent and needs .NET 10 Desktop Runtime x64 on the target PC. From the repository root:

```powershell
dotnet restore src/CodexProxyManager/CodexProxyManager.csproj
dotnet build src/CodexProxyManager/CodexProxyManager.csproj -c Release -r win-x64
dotnet build src/CodexProxyGuardian/CodexProxyGuardian.csproj -c Release -r win-x64
```

See [build details](docs/BUILD.md). Preserve the directory names under `third_party/`; the project references the pinned ProxiFyre release files there.

## Project layout

- `src/CodexProxyManager/` — WPF app and shared first-party services
- `src/CodexProxyGuardian/` — sign-in background component
- `third_party/` — pinned ProxiFyre 2.6.1 files and its own license/source
- `tools/` — icon generation, probes and focused project utilities
- `docs/` — architecture, build and safety scope

## Project status

Current source and tested desktop release: **v1.6**. The maintainer reports successful use of the no-reboot Guardian update. Protocol level Responses WebSocket, phone-side Remote Control, future Store updates and fault recovery remain separate checks; no unsupported end-to-end claim is made here.

## Contributing

Keep rules narrow and explicit. Do not include diagnostics, logs, user config, `results/`, or published build output in pull requests. Read [the coding-agent guide](.github/copilot-instructions.md) and third-party notices before changing the engine integration.