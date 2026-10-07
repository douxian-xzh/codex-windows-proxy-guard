# Build

## Requirements

- Windows x64
- .NET 10 SDK (WPF targeting pack included by the Windows SDK workload)
- .NET 10 Desktop Runtime x64 to run the published framework-dependent application

ProxiFyre 2.6.1 release files, upstream license/source snapshot, and hash lock are under `third_party/`. Preserve their existing directory names because the project files use those paths.

## Build commands

From the repository root:

```powershell
dotnet restore src/CodexProxyManager/CodexProxyManager.csproj
dotnet build src/CodexProxyManager/CodexProxyManager.csproj -c Release -r win-x64
dotnet build src/CodexProxyGuardian/CodexProxyGuardian.csproj -c Release -r win-x64
```

The commands above build the manager and Guardian for local development. A distributable package also needs the pinned ProxiFyre support files and third-party notices; do not publish the two projects independently as unrelated products because Guardian references the manager assembly.

Published binaries need the .NET 10 Desktop Runtime x64 installed on the user's computer. The runtime is not bundled.
