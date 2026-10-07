# Architecture

## Components

- **WPF manager**: configuration, target discovery, diagnostics, updates and tray UI.
- **CodexProxyGuardian**: per-user logon task, periodic discovery and protection health, and manager-independent lifecycle.
- **ProxiFyre 2.6.1**: upstream process-filtering service/engine. The manager applies a small set of verified executable-path rules and a SOCKS5 endpoint.
- **Original ChatGPT/Codex package**: launched from the normal Windows entry point. The manager's launch button is only a convenience shortcut.

The manager can close while Guardian and ProxiFyre continue. The normal update path refreshes the protected Guardian copy and logon task without rebooting Windows. A changed client path may require the engine configuration to reload; the Guardian defers an interrupting reload while the client is active.

## Scope and limits

Rules are path based, not PID isolation. The application does not add shared `python.exe`, `node.exe`, `git.exe`, PowerShell, command prompt, or system services as catch-all targets. Path rules may match another instance of the same executable at the same path.

This is not a machine-wide VPN, TUN, firewall kill switch, or promise that every system-brokered request is proxied. Driver/service outages, Windows brokered networking and unsupported engine traffic can fall outside the application's rules. Read the current ProxiFyre documentation and upstream license before installing it.

## Safety boundaries

The application does not set system proxy values, global `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`, DNS, hosts, routes, TLS validation, Windows Firewall policy, or ChatGPT sandbox settings. Guardian avoids interrupting an active ChatGPT/Codex session to reload rules.
