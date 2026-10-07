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

To publish the manager as a framework-dependent single-file WPF application and Guardian as a framework-dependent bundle, follow the `dotnet publish` commands in the root README. Do not publish the two projects independently as unrelated products: Guardian references the manager assembly, and the package also needs the pinned ProxiFyre support files and third-party notices.

Published binaries need the .NET 10 Desktop Runtime x64 installed on the user's computer. The runtime is not bundled.
