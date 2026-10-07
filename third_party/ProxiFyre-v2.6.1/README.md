# ProxiFyre 2.6.1 third-party dependency

- Upstream: <https://github.com/wiresock/proxifyre>
- Release/tag: `v2.6.1`
- Commit: `e04e7decd6ce4926580dc3c8d2078e32071a2091`
- License: GNU AGPL-3.0-only; see `LICENSE`.
- Upstream source archive: `proxifyre-v2.6.1-source.zip`.
- Release metadata and SHA-256 pins: `../ProxiFyre-v2.6.1-official-x64/dependency-lock.json`.

The manager uses the upstream release setup bootstrapper and `ProxiFyre.exe` and `socksify.dll` from the matching x64 release payload. Their hashes are pinned in the dependency lock. These are separate upstream components; the repository's root license does not relicense them.

The upstream bootstrapper is unsigned and may install Windows Packet Filter and Visual C++ prerequisites. Windows may show an unknown-publisher warning. Review the upstream source and license before installing the engine.

## Build

Build the manager and Guardian from the repository root using the commands in the root README. The project references the checked-in release assets by their original third-party paths. They are included to make a reproducible local build possible.

This application matches a narrow set of ChatGPT/Codex executable paths. It is not a machine-wide leak-proof firewall: system-brokered traffic, unsupported protocols, IPv6 fragments, or periods while the driver/service is unavailable are outside that guarantee. It does not enable a whole-machine TUN or edit the Windows proxy, global proxy environment variables, DNS, hosts, or default route.
