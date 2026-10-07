# Repository guide for coding agents

This is **Codex Windows Proxy Guardian**: a Windows WPF manager and logon Guardian that configure the upstream ProxiFyre engine for a narrow set of ChatGPT/Codex executable paths and a SOCKS5 endpoint.

- Keep changes inside the existing WPF/Guardian architecture; do not create a duplicate product or write a replacement packet driver/relay.
- Preserve the narrow explicit executable paths. Never add catch-all rules or shared interpreters/tools to hide a discovery gap.
- Do not edit Windows global proxy/environment settings, DNS, hosts, default routes, firewall policy, or TLS verification.
- Do not terminate all ChatGPT/Codex processes or stop the only engine/network path to validate a change.
- A Running service, open port, generic HTTPS request, or source build is not proof that Responses WebSocket or Remote Control works. Report those as unverified until real client evidence exists.
- Read `NOTICE.md` and third-party license files before changing or redistributing bundled components. The first-party source license does not relicense ProxiFyre.
- Keep diagnostics, user logs, local `results/`, release output, and personal machine paths out of commits.
