using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using System.Threading;
using System.Threading.Tasks;
using CodexProxyManager.Services;
using CodexProxyGuardian;

var passed = 0;
var failed = 0;
await Test("UI protection presentation never treats stale or missing background as Ready", TestProtectionPresentationAsync);
await Test("exact manifest path rules and supported JSON fields", TestScopeAndConfigAsync);
await Test("Windows AUMID activation validates discovered MSIX identity", TestActivationIdentityAsync);
await Test("MSIX discovery validates identity, component evidence, and narrow route targets", TestMsixComponentDiscoveryAsync);
await Test("proxy detector prioritizes saved endpoints and distinguishes protocol types", TestProxyEndpointDetectorAsync);
await Test("Guardian readiness requires SOCKS5 and current-rule proof", TestGuardianStateMachineAsync);
await Test("Guardian status reader rejects one-shot and dead-process snapshots", TestGuardianStatusReaderAsync);
await Test("Guardian login task uses a fixed protected executable and interactive highest token", TestGuardianTaskDefinitionAsync);
await Test("Guardian first enable requests only the verified fixed task once", TestGuardianImmediateRunAsync);
await Test("multiple-package selection, settings migration, and inaccessible-newer fail-closed", TestTargetDiscoveryAsync);
await Test("configuration ownership, backup, rollback, and drift refusal", TestConfigurationStoreAsync);
await Test("owned ProxiFyre config preserves unknown fields and records verified engine rules", TestConfigMergeAndEvidenceAsync);
await Test("verified protected engine-file replacement and rollback", TestProtectedFileTransactionAsync);
await Test("Codex log allowlist reports fallback and Remote failure without raw lines", TestCodexLogEvidenceAsync);
await Test("HTTP status and turn completion alone never imply WSS or Remote pass", TestCodexLogNoFalsePositiveAsync);
await Test("network diagnostics formats separate system DNS, interface, A, and AAAA evidence", TestNetworkDiagnosticsFormattingAsync);
await Test("ProxiFyre diagnostic logs redact credentials, identifiers, paths, and query strings", TestEngineLogRedactionAsync);
await Test("Windows SCM native entry points use exact advapi32 exports", TestScmNativeExportsAsync);
await Test("SOCKS5 no-auth CONNECT with fragmented reply", () => TestSocksAsync(MockMode.Success, "SocksConnect", true, null));
await Test("HTTP-only proxy is not classified as SOCKS5", () => TestSocksAsync(MockMode.Http, "SocksGreeting", false, null));
await Test("SOCKS5 authentication requirement is explicit", () => TestSocksAsync(MockMode.AuthRequired, "SocksAuthentication", false, null));
await Test("SOCKS5 CONNECT refusal is classified", () => TestSocksAsync(MockMode.Reject, "SocksConnect", false, "Reply0x05"));
await Test("SOCKS5 short response reports transport failure", () => TestSocksAsync(MockMode.Short, "SocksTransport", false, null));
await Test("SOCKS5 probe timeout is bounded", () => TestSocksAsync(MockMode.Hold, "Timeout", false, null, timeoutMs: 150));
await Test("SOCKS5 probe cancellation is honored", () => TestSocksAsync(MockMode.Hold, "Cancelled", false, null, cancelAfterMs: 80));

if (args is ["--live-socks"])
{
    if (!ProxyEndpoint.TryCreate("10.1.1.8", "7890", out var liveEndpoint, out var liveError))
    {
        Console.WriteLine("LIVE-SOCKS-PROBE: InvalidEndpoint: " + liveError);
        failed++;
    }
    else
    {
        try
        {
            var liveResult = await Socks5ProxyProbe.ProbeAsync(
                liveEndpoint!, "api.openai.com", 443, validateTls: true, tlsServerName: "api.openai.com",
                TimeSpan.FromSeconds(12), CancellationToken.None);
            Console.WriteLine($"LIVE-SOCKS-PROBE: {(liveResult.Success ? "Pass" : "Fail")}; stage={liveResult.Stage}; summary={liveResult.Summary}");
            if (!liveResult.Success) failed++;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"LIVE-SOCKS-PROBE: Fail; error={ex.GetType().Name}");
            failed++;
        }
    }
}

if (args is ["--live-network-diagnostics"])
{
    var snapshot = await NetworkDiagnosticsCollector.CaptureAsync();
    Console.WriteLine($"LIVE-NETWORK-DIAGNOSTICS: networkAvailable={snapshot.NetworkAvailable}; interfaces={snapshot.Interfaces.Count}; systemDnsServers={snapshot.SystemDnsServers.Count}");
    foreach (var host in snapshot.HostResolutions)
        Console.WriteLine($"LIVE-DNS: {host.Host}; status={host.Status}; A={host.Ipv4Addresses.Count}; AAAA={host.Ipv6Addresses.Count}; elapsedMs={host.DurationMs:F0}");
}

if (args is ["--live-dns-socks-compare", var comparisonPath])
{
    await CompareSystemDnsAndSocksTlsAsync(comparisonPath);
}

Console.WriteLine($"RESULT: {passed} passed, {failed} failed.");
var liveTargetDiscovery = new TargetApplicationService().DiscoverInstalled();
Console.WriteLine($"LIVE-DISCOVERY: {liveTargetDiscovery.Status}; package={liveTargetDiscovery.Application?.PackageFullName ?? "Unknown"}; exes={string.Join(" | ", liveTargetDiscovery.Application?.RuleExecutablePaths ?? Array.Empty<string>())}; detail={liveTargetDiscovery.Detail ?? "none"}");
if (liveTargetDiscovery.Application is { } liveTarget)
{
    Console.WriteLine("LIVE-COMPONENTS:");
    foreach (var component in liveTarget.KnownComponents)
        Console.WriteLine($"  {(component.IncludedInRule ? "ROUTE-CANDIDATE" : "DIAGNOSTIC-ONLY")}; {component.RelativePath}; {component.Role}; {component.Evidence}");
    TargetApplicationService.VerifyManifestRulePaths(liveTarget.InstallLocation, liveTarget.RuleExecutablePaths);
    var liveRuntime = new TargetApplicationService().CaptureRuntime(liveTarget);
    Console.WriteLine($"LIVE-COMPONENT-PROCESSES: {liveRuntime.KnownComponentProcesses.Count}");
    foreach (var process in liveRuntime.KnownComponentProcesses)
    {
        var image = process.ImagePath is null ? "Unknown" : Path.GetRelativePath(liveTarget.InstallLocation, process.ImagePath);
        var insidePackage = !Path.IsPathRooted(image)
            && !image.Equals("..", StringComparison.Ordinal)
            && !image.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal)
            && !image.StartsWith(".." + Path.AltDirectorySeparatorChar, StringComparison.Ordinal);
        Console.WriteLine($"  {process.Name}; PID={process.ProcessId}; PPID={process.ParentProcessId}; exactRulePath={process.ExactRuleTargetPath}; image={(insidePackage ? image : "outside-package (redacted)")}");
    }
    var familyProcesses = WindowsNativeSnapshot.ReadProcesses().Values
        .Where(process => string.Equals(process.Name, Path.GetFileName(liveTarget.ExecutablePath), StringComparison.OrdinalIgnoreCase))
        .Select(process => (process.ProcessId, Family: WindowsNativeSnapshot.ReadPackageFamilyName(process.ProcessId)))
        .Where(item => item.Family is not null)
        .ToArray();
    Console.WriteLine($"LIVE-PACKAGE-PROCESS-IDENTITIES: {familyProcesses.Length} ChatGPT.exe processes returned a package family name.");
    foreach (var process in familyProcesses)
        Console.WriteLine($"  PID={process.ProcessId}; packageFamilyName={process.Family}; matchesCurrent={string.Equals(process.Family, liveTarget.PackageFamilyName, StringComparison.OrdinalIgnoreCase)}");
}
return failed == 0 ? 0 : 1;

async Task Test(string name, Func<Task> body)
{
    try
    {
        await body();
        passed++;
        Console.WriteLine($"PASS: {name}");
    }
    catch (Exception ex)
    {
        failed++;
        Console.WriteLine($"FAIL: {name} — {ex.GetType().Name}: {ex.Message}");
    }
}

static Task TestScopeAndConfigAsync()
{
    var root = Path.Combine(Path.GetTempPath(), "WindowsApps", "OpenAI.Codex_26.930.7945.0_x64__2p2nqsd0c76g0");
    var chatPath = Path.Combine(root, "app", "ChatGPT.exe");
    var plan = ProxyScopePolicy.CreatePlan(root, [chatPath]);
    Assert(plan.ExecutablePaths.SequenceEqual([Path.GetFullPath(chatPath)], StringComparer.OrdinalIgnoreCase), "scope path not retained");

    var config = ProxiFyreConfigurationBuilder.Create(new ProxyEndpoint("10.1.1.8", 7890), plan);
    using var json = JsonDocument.Parse(config);
    var rule = json.RootElement.GetProperty("proxies").EnumerateArray().Single();
    Assert(rule.GetProperty("appNames").EnumerateArray().Single().GetString() == Path.GetFullPath(chatPath), "exact path missing");
    Assert(!config.Contains("includeChildren", StringComparison.OrdinalIgnoreCase), "invented includeChildren field");
    Assert(!config.Contains("packageFamilyName", StringComparison.OrdinalIgnoreCase), "invented package field");
    Assert(!config.Contains("remoteDns", StringComparison.OrdinalIgnoreCase), "invented remote DNS field");
    Assert(!config.Contains("\"pid\"", StringComparison.OrdinalIgnoreCase), "invented PID field");

    Throws<InvalidDataException>(() => ProxyScopePolicy.CreatePlan(root, [Path.Combine(root, "python.exe")]));
    Throws<InvalidDataException>(() => ProxyScopePolicy.CreatePlan(root, [root]));
    Throws<InvalidDataException>(() => ProxyScopePolicy.CreatePlan(root, [chatPath], [chatPath + ".backup.exe"]));
    ThrowsAny(() => ProxyScopePolicy.CreatePlan(root, [string.Empty]));
    Throws<InvalidDataException>(() => ProxyScopePolicy.CreatePlan(root, [Path.GetFullPath(Path.Combine(root, "..", "outside.exe"))]));

    Assert(!ProxyEndpoint.TryCreate(string.Empty, "7890", out _, out _), "empty proxy host accepted");
    Assert(!ProxyEndpoint.TryCreate("10.1.1.8", "0", out _, out _), "port zero accepted");
    Assert(!ProxyEndpoint.TryCreate("10.1.1.8", "65536", out _, out _), "port above 65535 accepted");
    Assert(ProxyEndpoint.TryCreate("2001:db8::1", "7890", out var ipv6Endpoint, out _) && ipv6Endpoint?.Display == "[2001:db8::1]:7890",
        "IPv6 literal endpoint was not accepted or formatted");
    return Task.CompletedTask;
}

static Task TestActivationIdentityAsync()
{
    const string packageFamilyName = "OpenAI.Codex_2p2nqsd0c76g0";
    var target = new TargetApplication(
        "ChatGPT", "26.930.7945.0", "OpenAI.Codex_26.930.7945.0_x64__2p2nqsd0c76g0",
        packageFamilyName, "ChatGPT", packageFamilyName + "!ChatGPT",
        @"C:\Program Files\WindowsApps\OpenAI.Codex_26.930.7945.0_x64__2p2nqsd0c76g0",
        @"C:\Program Files\WindowsApps\OpenAI.Codex_26.930.7945.0_x64__2p2nqsd0c76g0\app\ChatGPT.exe",
        Array.Empty<string>());

    Assert(WindowsApplicationActivator.GetValidatedAppUserModelId(target) == packageFamilyName + "!ChatGPT",
        "valid package family/application identity was rejected");
    Throws<InvalidDataException>(() => WindowsApplicationActivator.GetValidatedAppUserModelId(
        target with { AppUserModelId = packageFamilyName + "!DifferentApp" }));
    Throws<InvalidDataException>(() => WindowsApplicationActivator.GetValidatedAppUserModelId(
        target with { AppUserModelId = string.Empty }));
    return Task.CompletedTask;
}

static Task TestMsixComponentDiscoveryAsync()
{
    const string packageFullName = "OpenAI.Codex_26.930.7945.0_x64__2p2nqsd0c76g0";
    const string publisher = "CN=50BDFD77-8903-4850-9FFE-6E8522F64D5B";
    var root = Path.Combine(Path.GetTempPath(), "CodexProxyManager-MsixDiscovery", Guid.NewGuid().ToString("N"));
    var files = new[]
    {
        "app/ChatGPT.exe",
        "app/resources/codex-command-runner.exe",
        "app/resources/codex.exe",
        "app/resources/unreviewed-helper.exe",
        "app/Codex.exe",
        "app/resources/codex-code-mode-host.exe",
        "app/resources/codex-windows-sandbox-service.exe",
        "app/resources/codex-windows-sandbox-setup.exe"
    };
    Directory.CreateDirectory(root);
    foreach (var relative in files)
    {
        var path = Path.Combine(root, relative.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, "test executable placeholder");
    }

    XDocument MakeManifest() => XDocument.Parse($$"""
        <Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
                 xmlns:desktop2="http://schemas.microsoft.com/appx/manifest/desktop/windows10/2">
          <Identity Name="OpenAI.Codex" Version="26.930.7945.0" Publisher="{{publisher}}" />
          <Properties>
            <DisplayName>ChatGPT</DisplayName>
            <PublisherDisplayName>OpenAI</PublisherDisplayName>
          </Properties>
          <Applications>
            <Application Id="App" Executable="app/ChatGPT.exe" />
            <Application Id="CodexCoreCommandRunner" Executable="app/resources/codex-command-runner.exe" />
          </Applications>
          <Extensions>
            <desktop2:Extension Category="windows.firewallRules">
              <desktop2:FirewallRules Executable="app/resources/codex.exe">
                <desktop2:Rule Direction="in" IPProtocol="TCP" LocalPortMin="1455" LocalPortMax="1457" Profile="all" />
              </desktop2:FirewallRules>
              <desktop2:FirewallRules Executable="app/resources/unreviewed-helper.exe">
                <desktop2:Rule Direction="in" IPProtocol="TCP" LocalPortMin="1" LocalPortMax="1" Profile="all" />
              </desktop2:FirewallRules>
            </desktop2:Extension>
          </Extensions>
        </Package>
        """);

    try
    {
        var manifest = MakeManifest();
        var target = TargetApplicationService.ParseManifest(manifest, packageFullName, root);
        Assert(target.Version == "26.930.7945.0", "manifest version not read");
        Assert(target.Publisher == publisher && target.PublisherDisplayName == "OpenAI", "publisher identity fields not read");
        Assert(target.PackageFamilyName == "OpenAI.Codex_2p2nqsd0c76g0", "Windows PackageFamilyName API result mismatch");
        Assert(target.AppUserModelId == "OpenAI.Codex_2p2nqsd0c76g0!App", "AUMID did not use the Windows-derived package family name");

        var included = target.KnownComponents.Where(component => component.IncludedInRule).Select(component => component.RelativePath).ToHashSet(StringComparer.OrdinalIgnoreCase);
        Assert(included.SetEquals(["app/ChatGPT.exe", "app/resources/codex-command-runner.exe", "app/resources/codex.exe"]),
            "route target set included an unknown file or omitted a confirmed target");
        Assert(target.KnownComponents.Single(component => component.RelativePath == "app/resources/codex.exe").Evidence.Contains("不是已观察到的出站连接", StringComparison.Ordinal),
            "firewall declaration was incorrectly described as observed outbound traffic");
        Assert(!target.KnownComponents.Single(component => component.RelativePath == "app/resources/unreviewed-helper.exe").IncludedInRule,
            "unreviewed FirewallRules executable was silently routed");
        foreach (var relative in files.Where(path => path is "app/Codex.exe" or "app/resources/codex-code-mode-host.exe"
                                                      or "app/resources/codex-windows-sandbox-service.exe" or "app/resources/codex-windows-sandbox-setup.exe"
                                                      or "app/resources/unreviewed-helper.exe"))
            Assert(!target.KnownComponents.Single(component => component.RelativePath == relative).IncludedInRule,
                $"unconfirmed component was routed: {relative}");
        TargetApplicationService.VerifyRulePathsMatchManifest(target, target.RuleExecutablePaths);
        Throws<InvalidDataException>(() => TargetApplicationService.VerifyRulePathsMatchManifest(target, target.RuleExecutablePaths.Take(1).ToArray()));

        var routePlan = ProxyScopePolicy.CreatePlan(root, target.RuleExecutablePaths);
        var routeConfig = ProxiFyreConfigurationBuilder.Create(new ProxyEndpoint("10.1.1.8", 7890), routePlan);
        ProxiFyreConfigurationBuilder.Validate(routeConfig, target.RuleExecutablePaths);
        using (var routeJson = JsonDocument.Parse(routeConfig))
            Assert(routeJson.RootElement.GetProperty("proxies").EnumerateArray().Single().GetProperty("appNames").GetArrayLength() == 3,
                "ProxiFyre candidate config did not preserve the exact audited three-path scope");

        var updatedRoot = root + "-updated";
        try
        {
            Directory.CreateDirectory(updatedRoot);
            foreach (var relative in files)
            {
                var path = Path.Combine(updatedRoot, relative.Replace('/', Path.DirectorySeparatorChar));
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                File.WriteAllText(path, "updated test executable placeholder");
            }
            var updatedManifest = MakeManifest();
            updatedManifest.Descendants().Single(element => element.Name.LocalName == "Identity").SetAttributeValue("Version", "26.940.100.0");
            var updatedTarget = TargetApplicationService.ParseManifest(
                updatedManifest,
                "OpenAI.Codex_26.940.100.0_x64__2p2nqsd0c76g0",
                updatedRoot);
            Assert(updatedTarget.Version == "26.940.100.0" && updatedTarget.PackageFamilyName == target.PackageFamilyName,
                "a version-updated package did not retain its Windows-derived package family identity");
            Assert(updatedTarget.RuleExecutablePaths.All(path => path.StartsWith(Path.GetFullPath(updatedRoot) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)),
                "an updated package reused stale paths from its previous version directory");
        }
        finally { try { Directory.Delete(updatedRoot, recursive: true); } catch { } }

        var missingPublisher = MakeManifest();
        missingPublisher.Descendants().Single(element => element.Name.LocalName == "Identity").SetAttributeValue("Publisher", null);
        Throws<InvalidDataException>(() => TargetApplicationService.ParseManifest(missingPublisher, packageFullName, root));

        var mismatchedVersion = MakeManifest();
        mismatchedVersion.Descendants().Single(element => element.Name.LocalName == "Identity").SetAttributeValue("Version", "26.931.1.0");
        Throws<InvalidDataException>(() => TargetApplicationService.ParseManifest(mismatchedVersion, packageFullName, root));

        var traversal = MakeManifest();
        traversal.Descendants().Single(element => element.Name.LocalName == "Application"
            && (string?)element.Attribute("Id") == "App").SetAttributeValue("Executable", "../../outside.exe");
        Throws<InvalidDataException>(() => TargetApplicationService.ParseManifest(traversal, packageFullName, root));

        var codexPath = Path.Combine(root, "app", "resources", "codex.exe");
        File.Delete(codexPath);
        Throws<InvalidDataException>(() => TargetApplicationService.ParseManifest(MakeManifest(), packageFullName, root));
    }
    finally
    {
        try { Directory.Delete(root, recursive: true); } catch { }
    }

    return Task.CompletedTask;
}

static async Task TestProxyEndpointDetectorAsync()
{
    var saved = new AppSettings(false, "10.1.1.8", 7890, false);
    var system = new SystemProxyInfo(true, new ProxyEndpoint("127.0.0.1", 7897), false, false, 0, false, false, "固定代理");
    var current = new ProxyEndpoint("127.0.0.1", 9000);
    var candidates = ProxyEndpointDetector.BuildCandidates(current, saved, system);
    Assert(candidates.Count <= 9, "candidate scan exceeded its hard bound");
    Assert(candidates[0].Endpoint.Display == "10.1.1.8:7890" && candidates[0].Source == "已保存的自定义端点",
        "saved custom endpoint did not have first priority");
    Assert(candidates[1].Endpoint.Display == "127.0.0.1:7897" && candidates[1].Source == "Windows 固定系统代理",
        "system proxy candidate was not included after saved settings");
    Assert(candidates[2].Endpoint.Display == "127.0.0.1:9000", "current input candidate was not retained");
    Assert(candidates.Any(candidate => candidate.Endpoint.Display == "127.0.0.1:7890"),
        "known local loopback endpoint was not included when different from the saved LAN proxy");
    Assert(candidates.Any(candidate => candidate.Endpoint.Display == "127.0.0.1:7892"),
        "known mixed-port candidate was omitted");
    var edited = ProxyEndpointDetector.BuildCandidates(current, saved, system, currentInputDirty: true);
    Assert(edited[0].Endpoint.Display == current.Display && edited[0].Source == "当前未保存输入",
        "explicit unsaved current input did not take priority during a user-triggered scan");

    var socks = await DetectWithMockAsync(MockMode.Success, TimeSpan.FromMilliseconds(200));
    Assert(socks.Type == ProxyEndpointType.Socks5 && socks.Socks5Usable,
        $"valid anonymous SOCKS5 CONNECT classified incorrectly: {socks.Type} / {socks.Detail}");

    var authRequired = await DetectWithMockAsync(MockMode.AuthRequired, TimeSpan.FromMilliseconds(200));
    Assert(authRequired.Type == ProxyEndpointType.Socks5 && authRequired.Socks5ProtocolIdentified && !authRequired.Socks5Usable,
        "an authentication-required SOCKS5 endpoint was misclassified as usable or non-SOCKS");

    var httpOnly = await DetectWithHttpMockAsync(TimeSpan.FromMilliseconds(200));
    Assert(httpOnly.Type == ProxyEndpointType.HttpProxy && httpOnly.HttpConnectUsable && !httpOnly.Socks5Usable,
        "HTTP CONNECT endpoint was not classified separately from SOCKS5");

    var mixed = await DetectWithMixedMockAsync(TimeSpan.FromMilliseconds(400));
    Assert(mixed.Type == ProxyEndpointType.MixedPort && mixed.Socks5Usable && mixed.HttpConnectUsable,
        "an endpoint accepting both HTTP CONNECT and SOCKS5 was not classified as MixedPort");

    var portOpen = await DetectWithOpenPortMockAsync(TimeSpan.FromMilliseconds(120));
    Assert(portOpen.Type == ProxyEndpointType.PortOpen && !portOpen.Socks5Usable && !portOpen.HttpConnectUsable,
        "an open TCP port without a proxy protocol was incorrectly promoted to SOCKS5/HTTP");

    var unreachable = ProxyEndpointDetector.Classify(
        new Socks5ProbeResult(false, false, "TcpConnect", "ConnectionRefused"),
        new HttpConnectProbeResult(false, false, false, null, "TcpConnect", "ConnectionRefused"));
    Assert(unreachable == ProxyEndpointType.Unreachable, "connection-refused results were not classified Unreachable");

    var unknown = ProxyEndpointDetector.Classify(
        new Socks5ProbeResult(false, false, "Timeout", "timeout"),
        new HttpConnectProbeResult(false, false, false, null, "Timeout", "timeout"));
    Assert(unknown == ProxyEndpointType.Unknown, "unresolved network timeout was not kept Unknown");

    var nonProxyHttp = ProxyEndpointDetector.Classify(
        new Socks5ProbeResult(false, true, "SocksGreeting", "other protocol"),
        new HttpConnectProbeResult(true, false, false, 404, "HttpResponse", "not a proxy"));
    Assert(nonProxyHttp == ProxyEndpointType.Unknown, "a generic HTTP server response was mistaken for an HTTP proxy or plain open port");
}

static Task TestGuardianStateMachineAsync()
{
    static GuardianHealthInput AllPass() => new(
        "Found", true, true, true, true, true, true,
        GuardianCheckResult.Pass, GuardianCheckResult.Pass);

    Assert(GuardianHealthEvaluator.Evaluate(AllPass()).State == GuardianProtectionState.Ready,
        "all proven prerequisites should yield Ready");
    Assert(GuardianHealthEvaluator.Evaluate(AllPass() with { Socks5Check = GuardianCheckResult.Unknown }).State == GuardianProtectionState.Degraded,
        "unverified SOCKS5 must not yield Ready");
    Assert(GuardianHealthEvaluator.Evaluate(AllPass() with { CurrentRulesCheck = GuardianCheckResult.Unknown }).State == GuardianProtectionState.Degraded,
        "unverified current rules must not yield Ready");
    Assert(GuardianHealthEvaluator.Evaluate(AllPass() with { TargetDiscoveryStatus = "NotFound" }).State == GuardianProtectionState.CodexNotInstalled,
        "missing Codex install was not classified");
    Assert(GuardianHealthEvaluator.Evaluate(AllPass() with { ProxyEndpointConfigured = false }).State == GuardianProtectionState.ProxyUnavailable,
        "missing proxy endpoint was not classified");
    Assert(GuardianHealthEvaluator.Evaluate(AllPass() with { EngineRunning = false }).State == GuardianProtectionState.EngineUnavailable,
        "stopped engine was not classified");
    Assert(GuardianHealthEvaluator.Evaluate(AllPass() with { ConfigurationOwned = false }).State == GuardianProtectionState.ConfigInvalid,
        "unowned configuration was not classified");
    Assert(GuardianHealthEvaluator.Evaluate(AllPass() with { CurrentRulesCheck = GuardianCheckResult.Fail }).State == GuardianProtectionState.NeedsRepair,
        "mismatched current rules were not classified");
    Assert(GuardianHealthEvaluator.Evaluate(AllPass() with { Socks5Check = GuardianCheckResult.Fail }).State == GuardianProtectionState.ProxyUnavailable,
        "failed SOCKS5 check was not classified");

    var eligible = new GuardianPreparationInput(true, true, true, true, true, true, true, true, false, true, false);
    Assert(GuardianPreparationPolicy.Decide(eligible) == GuardianPreparationAction.AlreadyReady,
        "verified running protection should be left untouched");
    Assert(GuardianPreparationPolicy.Decide(eligible with { ServiceInstalled = false }) == GuardianPreparationAction.ManualSetupRequired,
        "Guardian must not silently install a missing driver/service");
    Assert(GuardianPreparationPolicy.Decide(eligible with { ConfigurationOwned = false }) == GuardianPreparationAction.ManualRepairRequired,
        "Guardian must refuse an unowned engine configuration");
    Assert(GuardianPreparationPolicy.Decide(eligible with { CurrentRulesPass = false, TargetRunning = true }) == GuardianPreparationAction.DeferForRunningCodex,
        "Guardian must defer a service restart while Codex is active");
    Assert(GuardianPreparationPolicy.Decide(eligible with { ServiceRunning = false, ServiceStopped = true, CurrentRulesPass = false }) == GuardianPreparationAction.AttemptRepair,
        "Guardian should prepare a stopped owned service after prerequisites pass");
    Assert(GuardianPreparationPolicy.Decide(eligible with { Socks5Validated = false }) == GuardianPreparationAction.WaitForSocks5,
        "Guardian must not start the engine before SOCKS5 protocol validation");
    Assert(GuardianPreparationPolicy.Decide(eligible with { ServiceRunning = false, ServiceStopped = false }) == GuardianPreparationAction.ManualRepairRequired,
        "Guardian must not act on a transitional/unknown service state");
    return Task.CompletedTask;
}

static Task TestGuardianStatusReaderAsync()
{
    var directory = Path.Combine(Path.GetTempPath(), "CodexProxyManager-GuardianReader", Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(directory);
    var path = Path.Combine(directory, "guardian-status.json");
    try
    {
        var captured = DateTimeOffset.UtcNow.ToString("O");
        File.WriteAllText(path, $$"""
            {"runtimeMode":"Once","processId":{{Environment.ProcessId}},"capturedAt":"{{captured}}","state":"Ready","detail":"test","proxyEndpointType":"MixedPort"}
            """);
        var once = GuardianStatusReader.Read(path);
        Assert(once.State == "Initializing" && !once.IsLive && once.ProxyEndpointType == "MixedPort",
            "one-shot Guardian output was accepted as live or omitted endpoint type diagnostics");

        File.WriteAllText(path, $$"""
            {"runtimeMode":"Background","processId":2147483647,"capturedAt":"{{captured}}","state":"Ready","detail":"test"}
            """);
        var dead = GuardianStatusReader.Read(path);
        Assert(dead.State == "Degraded" && !dead.IsLive, "dead Guardian PID was accepted as live");
    }
    finally
    {
        Directory.Delete(directory, recursive: true);
    }

    return Task.CompletedTask;
}

static Task TestGuardianTaskDefinitionAsync()
{
    var userSid = System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value
        ?? throw new InvalidOperationException("current user SID unavailable");
    var guardianPath = Path.Combine(GuardianTaskInstaller.GetInstallRoot(), "v-test", "CodexProxyGuardian.exe");
    var xml = GuardianTaskInstaller.BuildTaskXml(userSid, guardianPath);
    var document = XDocument.Parse(xml);
    var ns = document.Root?.Name.Namespace ?? XNamespace.None;
    Assert(document.Descendants(ns + "LogonType").Single().Value == "InteractiveToken", "Guardian task must use an existing interactive token");
    Assert(document.Descendants(ns + "RunLevel").Single().Value == "HighestAvailable", "Guardian task must request the user's highest available token");
    Assert(document.Descendants(ns + "UserId").All(element => element.Value == userSid), "Guardian trigger and principal must be scoped to the current SID");
    Assert(document.Descendants(ns + "Command").Single().Value == guardianPath, "task command escaped the protected Program Files install root");
    Assert(document.Descendants(ns + "Arguments").Single().Value == "--guardian", "task arguments are not the fixed Guardian mode");
    Assert(document.Descendants(ns + "AllowStartOnDemand").Single().Value == "true", "first enable must allow immediate task execution");
    Assert(document.Descendants(ns + "URI").Single().Value == GuardianTaskInstaller.TaskName, "task ownership marker is missing");
    Assert(!document.Descendants().Any(element => element.Name.LocalName.Contains("Password", StringComparison.OrdinalIgnoreCase)), "task definition must not store a password");
    Assert(xml.Contains("RestartOnFailure", StringComparison.Ordinal) && xml.Contains("<Count>3</Count>", StringComparison.Ordinal),
        "Guardian task restart policy must be bounded");
    Throws<InvalidDataException>(() => GuardianTaskInstaller.BuildTaskXml(userSid, Path.Combine(Environment.CurrentDirectory, "CodexProxyGuardian.exe")));
    return Task.CompletedTask;
}

static Task TestGuardianImmediateRunAsync()
{
    var calls = 0;
    Assert(!GuardianTaskInstaller.RequestImmediateRun(arguments => { calls++; return 0; }, false), "Unverified tasks must not run.");
    Assert(calls == 0, "Unverified task invoked the runner.");
    Assert(GuardianTaskInstaller.RequestImmediateRun(arguments =>
    {
        calls++;
        Assert(arguments.SequenceEqual(new[] { "/Run", "/TN", GuardianTaskInstaller.TaskName }), "Unexpected task or arbitrary command.");
        return 0;
    }, true), "Successful request wasn't acknowledged.");
    Assert(calls == 1, "Request must run only once.");
    Assert(!GuardianTaskInstaller.RequestImmediateRun(arguments => { calls++; return 1; }, true), "Rejected request was marked successful.");
    Assert(calls == 2, "Failed request must not retry.");
    return Task.CompletedTask;
}

static Task TestScmNativeExportsAsync()
{
    if (!OperatingSystem.IsWindows())
    {
        return Task.CompletedTask;
    }

    var library = NativeLibrary.Load("advapi32.dll");
    try
    {
        var exports = new[]
        {
            "OpenSCManagerW", "OpenServiceW", "CloseServiceHandle", "QueryServiceStatusEx", "StartServiceW", "ControlService"
        };
        foreach (var export in exports)
        {
            Assert(NativeLibrary.TryGetExport(library, export, out _), $"advapi32.dll does not export {export}");
        }

        var method = typeof(ProxyEngineService).GetMethod("OpenScManager", BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new InvalidOperationException("OpenScManager P/Invoke declaration not found");
        var import = method.GetCustomAttribute<DllImportAttribute>()
            ?? throw new InvalidOperationException("OpenScManager DllImport attribute not found");
        Assert(import.EntryPoint == "OpenSCManagerW" && import.ExactSpelling,
            $"OpenScManager import is not exact: entryPoint={import.EntryPoint ?? "(null)"}; exactSpelling={import.ExactSpelling}");

        var status = ProxyEngineService.GetStatus();
        Assert(status.Service != "状态未知" && status.Driver != "状态未知",
            $"read-only SCM status probe failed: service={status.Service}; driver={status.Driver}");
        Console.WriteLine($"READ-ONLY-SCM-STATUS: service={status.Service}; driver={status.Driver}");
    }
    finally
    {
        NativeLibrary.Free(library);
    }

    return Task.CompletedTask;
}

static Task TestConfigurationStoreAsync()
{
    var root = Path.Combine(Path.GetTempPath(), "CodexProxyManager-CoreSelfTest", Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(root);
    var configPath = Path.Combine(root, "app-config.json");
    var ownerPath = Path.Combine(root, "owner.json");
    try
    {
        var first = ManagedConfigurationStore.Apply(configPath, ownerPath, "{\"version\":1}");
        ManagedConfigurationStore.ValidateOwnership(configPath, ownerPath);
        var second = ManagedConfigurationStore.Apply(configPath, ownerPath, "{\"version\":2}");
        Assert(second.BackupDirectory is not null, "prior config backup not created");
        ManagedConfigurationStore.Rollback(configPath, ownerPath, second);
        Assert(File.ReadAllText(configPath) == "{\"version\":1}", "rollback did not restore previous config");
        ManagedConfigurationStore.ValidateOwnership(configPath, ownerPath);

        File.WriteAllText(configPath, "{\"external\":true}");
        Throws<InvalidOperationException>(() => ManagedConfigurationStore.ValidateOwnership(configPath, ownerPath));
        Throws<InvalidOperationException>(() => ManagedConfigurationStore.Apply(configPath, ownerPath, "{\"version\":3}"));
        Assert(File.ReadAllText(configPath) == "{\"external\":true}", "external change was overwritten");
    }
    finally
    {
        try { Directory.Delete(root, recursive: true); } catch { }
    }

    var absentRoot = Path.Combine(Path.GetTempPath(), "CodexProxyManager-CoreSelfTest", Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(absentRoot);
    try
    {
        var config = Path.Combine(absentRoot, "app-config.json");
        var owner = Path.Combine(absentRoot, "owner.json");
        var snapshot = ManagedConfigurationStore.Apply(config, owner, "{}\n");
        ManagedConfigurationStore.Rollback(config, owner, snapshot);
        Assert(!File.Exists(config) && !File.Exists(owner), "rollback did not restore previously absent state");
    }
    finally { try { Directory.Delete(absentRoot, recursive: true); } catch { } }
    return Task.CompletedTask;
}

static Task TestConfigMergeAndEvidenceAsync()
{
    var root = Path.Combine(Path.GetTempPath(), "CodexProxyManager-ConfigMergeTest", Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(root);
    try
    {
        var install = Path.Combine(root, "package");
        var executable = Path.Combine(install, "app", "ChatGPT.exe");
        var plan = ProxyScopePolicy.CreatePlan(install, [executable]);
        var endpoint = new ProxyEndpoint("10.1.1.8", 7890);
        var oldRulePath = Path.Combine(install, "old-version", "ChatGPT.exe");
        var oldConfig = $$"""
        {
          "logLevel": "Debug",
          "bypassLan": false,
          "excludes": ["127.0.0.1"],
          "futureRoot": { "preserve": true },
          "proxies": [{
            "appNames": [{{JsonSerializer.Serialize(oldRulePath)}}],
            "socks5ProxyEndpoint": "127.0.0.1:7897",
            "username": "",
            "password": "",
            "socks5Transport": "TCP",
            "supportedProtocols": ["TCP", "UDP"],
            "supportedAddressFamilies": ["IPv4", "IPv6"],
            "futureRule": { "mode": "keep" }
          }]
        }
        """;
        var merged = ProxiFyreConfigurationBuilder.CreateOrUpdate(endpoint, plan, oldConfig);
        ProxiFyreConfigurationBuilder.Validate(merged, plan.ExecutablePaths, endpoint);
        using (var json = JsonDocument.Parse(merged))
        {
            var document = json.RootElement;
            Assert(document.GetProperty("logLevel").GetString() == "Debug", "existing log level was not preserved");
            Assert(!document.GetProperty("bypassLan").GetBoolean(), "existing LAN bypass setting was not preserved");
            Assert(document.GetProperty("excludes")[0].GetString() == "127.0.0.1", "existing excludes were not preserved");
            Assert(document.GetProperty("futureRoot").GetProperty("preserve").GetBoolean(), "unknown root field was dropped");
            var rule = document.GetProperty("proxies")[0];
            Assert(rule.GetProperty("futureRule").GetProperty("mode").GetString() == "keep", "unknown rule field was dropped");
            Assert(rule.GetProperty("appNames")[0].GetString() == executable, "Codex update did not replace the prior package path");
            Assert(rule.GetProperty("socks5ProxyEndpoint").GetString() == endpoint.Display, "proxy endpoint was not refreshed");
        }

        Throws<InvalidDataException>(() => ProxiFyreConfigurationBuilder.CreateOrUpdate(endpoint, plan, "{\"proxies\":[{},{}]}"));
        Throws<InvalidDataException>(() => ProxiFyreConfigurationBuilder.CreateOrUpdate(endpoint, plan, "{\"future\":{\"pid\":123},\"proxies\":[]}"));

        var configPath = Path.Combine(root, "managed", "app-config.json");
        var ownerPath = Path.Combine(root, "managed", "CodexProxyManager.owner.json");
        Directory.CreateDirectory(Path.GetDirectoryName(configPath)!);
        var config = ProxiFyreConfigurationBuilder.Create(endpoint, plan);
        var snapshot = ManagedConfigurationStore.Apply(configPath, ownerPath, config);
        Assert(ManagedConfigurationStore.VerifyCurrentRules(configPath, ownerPath, endpoint, plan.ExecutablePaths).Status == "Unknown",
            "rules were marked ready before engine log verification");
        snapshot = ManagedConfigurationStore.RecordEngineReady(configPath, ownerPath, snapshot, endpoint, plan.ExecutablePaths, DateTimeOffset.UtcNow);
        Assert(ManagedConfigurationStore.VerifyCurrentRules(configPath, ownerPath, endpoint, plan.ExecutablePaths).Status == "Pass",
            "verified engine rule evidence was not accepted");
        File.AppendAllText(configPath, "\n");
        Assert(ManagedConfigurationStore.VerifyCurrentRules(configPath, ownerPath, endpoint, plan.ExecutablePaths).Status == "Fail",
            "config drift was not rejected after engine verification");
    }
    finally
    {
        try { Directory.Delete(root, recursive: true); } catch { }
    }

    return Task.CompletedTask;
}

static Task TestTargetDiscoveryAsync()
{
    var older = MakeTarget("26.900.1.0");
    var current = MakeTarget("26.930.1.0");
    var updated = TargetApplicationService.ResolveDiscovery([older, current], []);
    Assert(updated.Status == "Found" && updated.Application?.Version == current.Version,
        "same-family side-by-side versions did not select the newest package automatically");
    var staleSelection = TargetApplicationService.ResolveDiscovery([older, current], [], older.PackageFullName);
    Assert(staleSelection.Status == "Found" && staleSelection.Application?.Version == current.Version,
        "a saved older package selection blocked automatic update discovery");

    var otherFamily = current with
    {
        PackageFullName = "OpenAI.Codex_26.930.1.0_x64__otherpublisher",
        PackageFamilyName = "OpenAI.Codex_otherpublisher",
        AppUserModelId = "OpenAI.Codex_otherpublisher!App"
    };
    var requiresChoice = TargetApplicationService.ResolveDiscovery([current, otherFamily], []);
    Assert(requiresChoice.Status == "SelectionRequired" && requiresChoice.Application is null && requiresChoice.Candidates?.Count == 2,
        "different package families did not require an explicit selection");
    var explicitSelection = TargetApplicationService.ResolveDiscovery([current, otherFamily], [], otherFamily.PackageFullName);
    Assert(explicitSelection.Status == "Found" && explicitSelection.Application?.PackageFamilyName == otherFamily.PackageFamilyName,
        "an explicit selection did not preserve the chosen package family");

    var inaccessibleNewer = TargetApplicationService.ResolveDiscovery(
        [older], [new TargetDiscoveryFailure(new Version(26, 940, 1, 0), "newer manifest inaccessible")]);
    Assert(inaccessibleNewer.Status == "Unknown" && inaccessibleNewer.Application is null, "silently fell back to an older install after a newer package became inaccessible");

    var noInstall = TargetApplicationService.ResolveDiscovery([], []);
    Assert(noInstall.Status == "NotFound", "empty package set was not reported as NotFound");
    var legacySettings = JsonSerializer.Deserialize<AppSettings>("{\"FollowSystemProxy\":false,\"CustomHost\":\"10.1.1.8\",\"CustomPort\":7890,\"RunAtLogon\":false}");
    Assert(legacySettings is not null && legacySettings.SelectedPackageFullName is null, "existing user settings did not load without the new optional package field");
    return Task.CompletedTask;
}

static Task TestProtectedFileTransactionAsync()
{
    var root = Path.Combine(Path.GetTempPath(), "CodexProxyManager-file-selftest-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(root);
    try
    {
        var payloadPath = Path.Combine(root, "payload.bin");
        var targetPath = Path.Combine(root, "install", "engine.bin");
        var backupRoot = Path.Combine(root, "backups", "one");
        var original = Encoding.UTF8.GetBytes("official-old");
        var candidate = Encoding.UTF8.GetBytes("official-new");
        File.WriteAllBytes(payloadPath, candidate);
        var expectedHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(candidate));
        Assert(ProtectedFileTransaction.ReadVerifiedPayload(payloadPath, expectedHash, "test payload").SequenceEqual(candidate), "verified payload bytes changed");
        Throws<InvalidDataException>(() => ProtectedFileTransaction.ReadVerifiedPayload(payloadPath, "00", "test payload"));

        Directory.CreateDirectory(Path.GetDirectoryName(targetPath)!);
        File.WriteAllBytes(targetPath, original);
        var replacement = ProtectedFileTransaction.Replace(targetPath, candidate, backupRoot);
        Assert(File.ReadAllBytes(targetPath).SequenceEqual(candidate), "candidate was not installed atomically");
        ProtectedFileTransaction.Restore(replacement);
        Assert(File.ReadAllBytes(targetPath).SequenceEqual(original), "previous engine file was not restored");

        var absentTarget = Path.Combine(root, "install", "new.dll");
        var absent = ProtectedFileTransaction.Replace(absentTarget, candidate, backupRoot);
        ProtectedFileTransaction.Restore(absent);
        Assert(!File.Exists(absentTarget), "new file was not removed during rollback");

        var drift = ProtectedFileTransaction.Replace(targetPath, candidate, backupRoot);
        File.WriteAllText(targetPath, "external-change");
        Throws<InvalidOperationException>(() => ProtectedFileTransaction.Restore(drift));
        Assert(File.ReadAllText(targetPath) == "external-change", "external file modification was overwritten");
    }
    finally { try { Directory.Delete(root, recursive: true); } catch { } }
    return Task.CompletedTask;
}

static TargetApplication MakeTarget(string version)
{
    var root = Path.Combine(Path.GetTempPath(), "WindowsApps", "OpenAI.Codex_" + version + "_x64__2p2nqsd0c76g0");
    var executable = Path.Combine(root, "app", "ChatGPT.exe");
    var package = $"OpenAI.Codex_{version}_x64__2p2nqsd0c76g0";
    return new TargetApplication("ChatGPT", version, package, "OpenAI.Codex_2p2nqsd0c76g0", "App", "OpenAI.Codex_2p2nqsd0c76g0!App", root, executable, [executable]);
}

static Task TestCodexLogEvidenceAsync()
{
    var path = Path.Combine(Path.GetTempPath(), "CodexProxyManager-log-selftest-" + Guid.NewGuid().ToString("N") + ".log");
    const string dummy = "Authorization: Bearer TEST_SECRET_DO_NOT_EXPORT";
    try
    {
        File.WriteAllText(path, string.Join(Environment.NewLine,
        [
            "transport=\"responses_websocket\"",
            "turn.completed",
            "falling back from WebSockets to HTTPS transport",
            "hostKind=durable failureReason=open_timeout websocket close code 1006",
            dummy,
            "prompt body that must never be retained"
        ]));
        var evidence = CodexLogEvidenceReader.Read(path);
        Assert(evidence.ResponsesStatus == "FallbackObserved", "fallback was not classified");
        Assert(evidence.RemoteStatus == "RemoteFailureObserved", "Remote failure was not classified");
        Assert(!evidence.ToString().Contains("TEST_SECRET", StringComparison.Ordinal), "dummy secret leaked into evidence");
        Assert(!evidence.ToString().Contains("prompt body", StringComparison.Ordinal), "prompt text leaked into evidence");
    }
    finally { try { File.Delete(path); } catch { } }
    return Task.CompletedTask;
}

static Task TestCodexLogNoFalsePositiveAsync()
{
    var path = Path.Combine(Path.GetTempPath(), "CodexProxyManager-log-selftest-" + Guid.NewGuid().ToString("N") + ".txt");
    try
    {
        File.WriteAllText(path, "HTTP 426\r\nturn.completed\r\nResponses WebSocket timed out; HTTPS fallback may still work\r\n");
        var evidence = CodexLogEvidenceReader.Read(path);
        Assert(evidence.ResponsesStatus == "WebSocketFailureObserved", "HTTP status, turn completion, or a possible fallback was promoted to WSS pass/fallback");
        Assert(evidence.RemoteStatus == "Unknown", "HTTP reachability was promoted to Remote pass");
        Throws<InvalidDataException>(() => CodexLogEvidenceReader.Read(Path.ChangeExtension(path, ".jsonl")));
    }
    finally { try { File.Delete(path); } catch { } }
    return Task.CompletedTask;
}

static Task TestNetworkDiagnosticsFormattingAsync()
{
    var snapshot = new NetworkDiagnosticsSnapshot(
        DateTimeOffset.UnixEpoch,
        true,
        ["192.0.2.53"],
        [new NetworkInterfaceDiagnostic("test adapter", "Ethernet", "Up", ["192.0.2.10", "2001:db8::10"], ["192.0.2.53"])],
        [new HostDnsDiagnostic("api.openai.com", "Resolved via system DNS resolver", ["192.0.2.20"], ["2001:db8::20"], 12)]);
    var formatted = snapshot.Format();
    Assert(formatted.Contains("192.0.2.53", StringComparison.Ordinal), "system DNS server missing");
    Assert(formatted.Contains("A=[192.0.2.20]", StringComparison.Ordinal), "A result missing or merged");
    Assert(formatted.Contains("AAAA=[2001:db8::20]", StringComparison.Ordinal), "AAAA result missing or merged");
    Assert(formatted.Contains("system DNS resolver", StringComparison.OrdinalIgnoreCase), "resolver semantics missing");
    return Task.CompletedTask;
}

static Task TestEngineLogRedactionAsync()
{
    var source = new[]
    {
        "Authorization: Bearer authSecret",
        "Cookie: sid=sessionSecret; domain=private.example",
        "account_id=acctSecret device_id=deviceSecret token=tokenSecret",
        "socks5://user:socksSecret@127.0.0.1:7890",
        "https://example.invalid/path?access_token=querySecret",
        "C:\\Users\\alice\\profile"
    };
    var redacted = string.Join(Environment.NewLine, source.Select(ProxyEngineService.RedactEngineLogLine));
    foreach (var secret in new[] { "authSecret", "sessionSecret", "private.example", "acctSecret", "deviceSecret", "tokenSecret", "socksSecret", "querySecret", "alice" })
        Assert(!redacted.Contains(secret, StringComparison.OrdinalIgnoreCase), "diagnostic log leaked " + secret);
    Assert(redacted.Contains("[REDACTED]", StringComparison.Ordinal), "redaction marker missing");
    return Task.CompletedTask;
}

static async Task TestSocksAsync(MockMode mode, string expectedStage, bool expectedSuccess, string? expectedReply, int timeoutMs = 1000, int? cancelAfterMs = null)
{
    using var listener = new TcpListener(IPAddress.Loopback, 0);
    listener.Start();
    var port = ((IPEndPoint)listener.LocalEndpoint).Port;
    using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(4));
    var serverTask = ServeMockAsync(listener, mode, serverCancellation.Token);
    using var cancellation = new CancellationTokenSource();
    if (cancelAfterMs.HasValue) cancellation.CancelAfter(cancelAfterMs.Value);
    var result = await Socks5ProxyProbe.ProbeAsync(
        new ProxyEndpoint("127.0.0.1", port), "api.openai.com", 443, false, null,
        TimeSpan.FromMilliseconds(timeoutMs), cancellation.Token);
    Assert(result.Stage == expectedStage, $"expected stage {expectedStage}, actual {result.Stage}: {result.Summary}");
    Assert(result.Success == expectedSuccess, $"expected success {expectedSuccess}, actual {result.Success}");
    if (expectedReply is not null) Assert(result.ReplyCode == expectedReply, $"expected {expectedReply}, actual {result.ReplyCode}");
    await serverTask;
}

static async Task<ProxyEndpointProbeResult> DetectWithMockAsync(MockMode mode, TimeSpan timeout)
{
    using var listener = new TcpListener(IPAddress.Loopback, 0);
    listener.Start();
    var endpoint = new ProxyEndpoint("127.0.0.1", ((IPEndPoint)listener.LocalEndpoint).Port);
    using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(4));
    var serverTask = ServeMockAsync(listener, mode, serverCancellation.Token);
    var result = await ProxyEndpointDetector.ProbeEndpointAsync(endpoint, "LocalMock", timeout);
    await serverTask;
    return result;
}

static async Task<ProxyEndpointProbeResult> DetectWithHttpMockAsync(TimeSpan timeout)
{
    using var listener = new TcpListener(IPAddress.Loopback, 0);
    listener.Start();
    var endpoint = new ProxyEndpoint("127.0.0.1", ((IPEndPoint)listener.LocalEndpoint).Port);
    using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(4));
    var serverTask = ServeHttpProxyAsync(listener, serverCancellation.Token);
    var result = await ProxyEndpointDetector.ProbeEndpointAsync(endpoint, "LocalHttpMock", timeout);
    await serverTask;
    return result;
}

static async Task<ProxyEndpointProbeResult> DetectWithMixedMockAsync(TimeSpan timeout)
{
    using var listener = new TcpListener(IPAddress.Loopback, 0);
    listener.Start();
    var endpoint = new ProxyEndpoint("127.0.0.1", ((IPEndPoint)listener.LocalEndpoint).Port);
    using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(4));
    var serverTask = ServeMixedProxyAsync(listener, serverCancellation.Token);
    var result = await ProxyEndpointDetector.ProbeEndpointAsync(endpoint, "LocalMixedMock", timeout);
    await serverTask;
    return result;
}

static async Task<ProxyEndpointProbeResult> DetectWithOpenPortMockAsync(TimeSpan timeout)
{
    using var listener = new TcpListener(IPAddress.Loopback, 0);
    listener.Start();
    var endpoint = new ProxyEndpoint("127.0.0.1", ((IPEndPoint)listener.LocalEndpoint).Port);
    using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(4));
    var serverTask = ServeOpenPortAsync(listener, serverCancellation.Token);
    var result = await ProxyEndpointDetector.ProbeEndpointAsync(endpoint, "LocalOpenPortMock", timeout);
    await serverTask;
    return result;
}

static async Task ServeMockAsync(TcpListener listener, MockMode mode, CancellationToken cancellationToken)
{
    using var client = await listener.AcceptTcpClientAsync(cancellationToken);
    await using var stream = client.GetStream();
    if (mode == MockMode.Http)
    {
        await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection established\r\n\r\n"), cancellationToken);
        await Task.Delay(100, cancellationToken);
        return;
    }

    if (mode == MockMode.Hold)
    {
        await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken).ContinueWith(_ => { });
        return;
    }

    var greeting = new byte[3];
    await ReadExactlyAsync(stream, greeting, cancellationToken);
    if (mode == MockMode.AuthRequired)
    {
        await stream.WriteAsync(new byte[] { 0x05 }, cancellationToken);
        await Task.Delay(15, cancellationToken);
        await stream.WriteAsync(new byte[] { 0x02 }, cancellationToken);
        return;
    }

    await stream.WriteAsync(new byte[] { 0x05 }, cancellationToken);
    await Task.Delay(15, cancellationToken);
    await stream.WriteAsync(new byte[] { 0x00 }, cancellationToken);
    if (mode == MockMode.Short) return;

    var header = new byte[4];
    await ReadExactlyAsync(stream, header, cancellationToken);
    Assert(header[0] == 5 && header[1] == 1 && header[3] == 3, "probe did not send a SOCKS5 domain CONNECT request");
    var domainLength = new byte[1];
    await ReadExactlyAsync(stream, domainLength, cancellationToken);
    var domain = new byte[domainLength[0] + 2];
    await ReadExactlyAsync(stream, domain, cancellationToken);
    Assert(Encoding.ASCII.GetString(domain, 0, domainLength[0]) == "api.openai.com", "target domain was not sent via SOCKS5");

    var reply = mode == MockMode.Reject
        ? new byte[] { 0x05, 0x05, 0x00, 0x01, 127, 0, 0, 1, 0x12, 0x34 }
        : new byte[] { 0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x12, 0x34 };
    foreach (var value in reply)
    {
        await stream.WriteAsync(new[] { value }, cancellationToken);
        await Task.Delay(5, cancellationToken);
    }
}

static async Task ServeHttpProxyAsync(TcpListener listener, CancellationToken cancellationToken)
{
    using (var socksProbe = await listener.AcceptTcpClientAsync(cancellationToken))
    {
        await using var stream = socksProbe.GetStream();
        await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection established\r\n\r\n"), cancellationToken);
    }

    using (var httpProbe = await listener.AcceptTcpClientAsync(cancellationToken))
    {
        await using var stream = httpProbe.GetStream();
        await ReadHttpHeadersAsync(stream, cancellationToken);
        await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection established\r\n\r\n"), cancellationToken);
    }
}

static async Task ServeMixedProxyAsync(TcpListener listener, CancellationToken cancellationToken)
{
    using (var socksProbe = await listener.AcceptTcpClientAsync(cancellationToken))
    {
        await using var stream = socksProbe.GetStream();
        var greeting = new byte[3];
        await ReadExactlyAsync(stream, greeting, cancellationToken);
        Assert(greeting.SequenceEqual(new byte[] { 0x05, 0x01, 0x00 }), "detector did not offer anonymous SOCKS5");
        await stream.WriteAsync(new byte[] { 0x05, 0x00 }, cancellationToken);
        var requestHeader = new byte[4];
        await ReadExactlyAsync(stream, requestHeader, cancellationToken);
        Assert(requestHeader[0] == 5 && requestHeader[1] == 1 && requestHeader[3] == 3, "detector did not send domain-name SOCKS5 CONNECT");
        var domainLength = new byte[1];
        await ReadExactlyAsync(stream, domainLength, cancellationToken);
        var domainAndPort = new byte[domainLength[0] + 2];
        await ReadExactlyAsync(stream, domainAndPort, cancellationToken);
        await stream.WriteAsync(new byte[] { 0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80 }, cancellationToken);
    }

    using (var httpProbe = await listener.AcceptTcpClientAsync(cancellationToken))
    {
        await using var stream = httpProbe.GetStream();
        await ReadHttpHeadersAsync(stream, cancellationToken);
        await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection established\r\n\r\n"), cancellationToken);
    }
}

static async Task ServeOpenPortAsync(TcpListener listener, CancellationToken cancellationToken)
{
    using var first = await listener.AcceptTcpClientAsync(cancellationToken);
    using var second = await listener.AcceptTcpClientAsync(cancellationToken);
    await Task.Delay(500, cancellationToken);
}

static async Task ReadHttpHeadersAsync(Stream stream, CancellationToken cancellationToken)
{
    var bytes = new List<byte>(256);
    var one = new byte[1];
    while (bytes.Count < 2048)
    {
        var read = await stream.ReadAsync(one, cancellationToken);
        if (read == 0) throw new EndOfStreamException("HTTP probe closed before request headers ended.");
        bytes.Add(one[0]);
        if (bytes.Count >= 4 && bytes[^4] == '\r' && bytes[^3] == '\n' && bytes[^2] == '\r' && bytes[^1] == '\n')
            return;
    }
    throw new InvalidDataException("HTTP request headers exceeded the test limit.");
}

static async Task ReadExactlyAsync(Stream stream, Memory<byte> buffer, CancellationToken cancellationToken)
{
    var offset = 0;
    while (offset < buffer.Length)
    {
        var read = await stream.ReadAsync(buffer[offset..], cancellationToken);
        if (read == 0) throw new EndOfStreamException();
        offset += read;
    }
}

static async Task CompareSystemDnsAndSocksTlsAsync(string outputPath)
{
    var settingsService = new ProxySettingsService();
    var settings = settingsService.Load();
    var endpoint = settings is { FollowSystemProxy: false }
        ? ProxyEndpoint.TryCreate(settings.CustomHost ?? "", settings.CustomPort?.ToString() ?? "", out var saved, out _) ? saved : null
        : settingsService.ReadSystemProxy().Endpoint;
    if (endpoint is null) throw new InvalidOperationException("No configured endpoint; no candidates are automatically substituted.");

    var snapshot = await NetworkDiagnosticsCollector.CaptureAsync();
    var inputs = snapshot.HostResolutions.SelectMany(host =>
        new[] { (Host: host.Host, Mode: "SocksDomain", Destination: (string?)host.Host) }
            .Concat(new[]
            {
                (Host: host.Host, Mode: "SystemAPlusSni", Destination: host.Ipv4Addresses.FirstOrDefault()),
                (Host: host.Host, Mode: "SystemAaaaPlusSni", Destination: host.Ipv6Addresses.FirstOrDefault())
            })).ToArray();
    using var concurrency = new SemaphoreSlim(2);
    var results = await Task.WhenAll(inputs.Select(async input =>
    {
        if (input.Destination is null)
            return new { host = input.Host, mode = input.Mode, destination = input.Destination, status = "NotTested", stage = "NoSystemDnsAnswer", tlsProtocol = (string?)null, durationMs = 0d };
        await concurrency.WaitAsync();
        try
        {
            var result = await Socks5ProxyProbe.ProbeAsync(endpoint, input.Destination, 443,
                validateTls: true, tlsServerName: input.Host, timeout: TimeSpan.FromSeconds(8));
            return new { host = input.Host, mode = input.Mode, destination = (string?)input.Destination, status = result.Success ? "Pass" : "Fail", stage = result.Stage, tlsProtocol = result.TlsProtocol, durationMs = result.DurationMs };
        }
        finally { concurrency.Release(); }
    }));
    var report = new
    {
        capturedAt = snapshot.CapturedAt,
        endpoint = endpoint.Display,
        managerVersion = typeof(ProxySettingsService).Assembly.GetName().Version?.ToString(),
        tlsCertificateValidation = "Default system validation; SNI is the original host for all modes",
        scope = "Explicit SOCKS5 diagnostics; not transparent interception, real Codex WSS, Remote or final proxy egress policy",
        systemDnsServers = snapshot.SystemDnsServers,
        dns = snapshot.HostResolutions,
        results,
        productionSettingsModified = false
    };
    var fullPath = Path.GetFullPath(outputPath);
    Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
    await File.WriteAllTextAsync(fullPath, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
    foreach (var result in results)
        Console.WriteLine($"LIVE-DNS-SOCKS-COMPARE: {result.host}; {result.mode}; {result.status}; {result.stage}; TLS={result.tlsProtocol ?? "none"}");
}

static Task TestProtectionPresentationAsync()
{
    var status = new GuardianStatusView("Ready", "rule proof", true, DateTimeOffset.Now,
        "127.0.0.1:7897", "Pass", "Running", "Running", "Pass", "26.930");
    var ready = ProtectionPresentation.From(status, true);
    Assert(ready.Tone == "Ready" && !ready.Title.Contains("连接已通过"), "Ready describes background readiness only.");
    Assert(ProtectionPresentation.From(status with { IsLive = false }, true).Tone == "Warning", "Stale Ready must never stay green.");
    Assert(ProtectionPresentation.From(status with { State = "ProxyUnavailable" }, true).NextAction.Contains("连接设置"), "Proxy failure needs an actionable instruction.");
    foreach (var state in new[] { "EngineUnavailable", "ConfigInvalid", "CodexNotInstalled", "NeedsRepair", "Degraded", "Unknown" })
        Assert(ProtectionPresentation.From(status with { State = state }, true).Tone == "Warning", "Failure states must remain warnings: " + state);
    Assert(ProtectionPresentation.From(status with { State = "Initializing" }, true).Tone == "Neutral", "Initializing isn't protected.");
    Assert(ProtectionPresentation.From(status, false).NextAction.Contains("登录后"), "Ready without login registration needs the next-login hint.");
    return Task.CompletedTask;
}

static void Assert(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
}

static void Throws<T>(Action action) where T : Exception
{
    try { action(); }
    catch (T) { return; }
    throw new InvalidOperationException($"Expected {typeof(T).Name}.");
}

static void ThrowsAny(Action action)
{
    try { action(); }
    catch (Exception) { return; }
    throw new InvalidOperationException("Expected a rejected invalid input.");
}

enum MockMode { Success, Http, AuthRequired, Reject, Short, Hold }
