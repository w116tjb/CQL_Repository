// Claude Code extension (Cursor marketplace) trojan - NGSIEM threat hunts
// Sources: StepSecurity, Cursor security notice, Microsoft Threat Intelligence (Oct 29-30, 2026)
// Recommended time range: 2026-10-29 00:00 UTC -> now

// ================= h1_exposure.cql =================
// Hunt 1 - Exposure: Falcon telemetry referencing the affected extension folders
#repo=base_sensor
| case {
    TargetFileName=/anthropic\.claude-code-2\.1\.31[23]-/iF | ArtifactPath := TargetFileName ;
    ImageFileName=/anthropic\.claude-code-2\.1\.31[23]-/iF | ArtifactPath := ImageFileName ;
    CommandLine=/anthropic\.claude-code-2\.1\.31[23]-/iF | ArtifactPath := CommandLine ;
  }
// Intentional: no * fall-through - only events that touch the extension folders survive
| ArtifactPath=/anthropic\.claude-code-(?<ExtVersion>2\.1\.31[23])-(?<ExtPlatform>[a-z0-9]+-[a-z0-9]+)/i
| case {
    ArtifactPath=/[\\\/]\.cursor[\\\/]/iF | Editor := "Cursor" ;
    ArtifactPath=/[\\\/]\.vscode(-insiders)?[\\\/]/iF | Editor := "VS Code" ;
    * | Editor := "Other" ;
  }
| case {
    ExtVersion="2.1.313" | Risk := "HIGH - 2.1.313 exists only as the malicious build" ;
    Editor="Cursor" | Risk := "HIGH - 2.1.312 under Cursor (malicious if installed in window)" ;
    * | Risk := "LOW - 2.1.312 outside Cursor (Open-VSX/MS build verified clean)" ;
  }
| groupBy([aid, ExtVersion, ExtPlatform, Editor, Risk],
    function=[count(as=Events),
              min(@timestamp, as=FirstSeen),
              max(@timestamp, as=LastSeen),
              collect([#event_simpleName], limit=10),
              selectLast([ArtifactPath])],
    limit=max)
| match(file="aid_master_main.csv", field=[aid], column=aid, include=[ComputerName], strict=false)
| sort(Risk, order=asc, limit=1000)
| formatTime(format="%F %T %Z", field=FirstSeen, as=FirstSeen)
| formatTime(format="%F %T %Z", field=LastSeen, as=LastSeen)
| table([ComputerName, aid, Risk, ExtVersion, ExtPlatform, Editor, FirstSeen, LastSeen, Events, "#event_simpleName", ArtifactPath], limit=1000)

// ================= h2_c2_falcon.cql =================
// Hunt 2 - Falcon network connections to the attacker C2 (SSH :22 tunnel, HTTP :8099 beacon)
#event_simpleName=NetworkConnectIP4 RemoteAddressIP4="134.209.82.225"
| groupBy([aid, ContextProcessId],
    function=[count(as=Connections),
              collect([RemotePort], limit=10),
              min(@timestamp, as=FirstSeen),
              max(@timestamp, as=LastSeen)],
    limit=max)
| match(file="aid_master_main.csv", field=[aid], column=aid, include=[ComputerName], strict=false)
| ProcessExplorer := format("[Process Explorer](https://falcon.crowdstrike.com/investigate/process-explorer/%s/%s)", field=[aid, ContextProcessId])
| sort(LastSeen, order=desc, limit=1000)
| formatTime(format="%F %T %Z", field=FirstSeen, as=FirstSeen)
| formatTime(format="%F %T %Z", field=LastSeen, as=LastSeen)
| table([ComputerName, aid, RemotePort, Connections, FirstSeen, LastSeen, ProcessExplorer], limit=1000)

// ================= h3_c2_paloalto.cql =================
// Hunt 3 - Perimeter view: Palo Alto NGFW / Prisma Access traffic to the C2
#Vendor=paloalto
| in(field=#event.module, values=["ngfw", "prisma"])
| (destination.ip="134.209.82.225" OR url.original=/134\.209\.82\.225/F)
| Dataset := #event.dataset
| groupBy([source.ip, user.name, Dataset],
    function=[count(as=Sessions),
              collect([destination.port, event.action], limit=10),
              min(@timestamp, as=FirstSeen),
              max(@timestamp, as=LastSeen)],
    limit=max)
// Post-aggregation: map source IP to a sensor host (DHCP churn - treat as a lead)
| match(file="aid_master_main.csv", field=[source.ip], column=LocalAddressIP4, include=[ComputerName, aid], strict=false)
| sort(LastSeen, order=desc, limit=1000)
| formatTime(format="%F %T %Z", field=FirstSeen, as=FirstSeen)
| formatTime(format="%F %T %Z", field=LastSeen, as=LastSeen)
| table([source.ip, ComputerName, aid, user.name, Dataset, destination.port, event.action, Sessions, FirstSeen, LastSeen], limit=1000)

// ================= h4_process.cql =================
// Hunt 4 - Loader command lines: tunnel, persistence, SSH enablement
#event_simpleName=ProcessRollup2
| in(field=FileName, values=["ssh.exe", "ssh", "autossh", "schtasks.exe", "systemsetup", "powershell.exe", "pwsh.exe", "pwsh", "launchctl", "crontab", "sh", "bash", "zsh", "cmd.exe"], ignoreCase=true)
// Intentional: no * fall-through - drop processes that match no indicator
| case {
    CommandLine=/134\.209\.82\.225|svc-telemetry/iF | Indicator := "C2 IP or implant key comment" | Confidence := "1-Confirmed IOC" ;
    CommandLine=/\.stk_[0-9a-f]{10}|\.config[\\\/](\.smtk?|smtk|smt\.cmd)|com\.apple\.sysmond|Startup[\\\/]sysmon\.cmd/iF | Indicator := "Loader artifact path" | Confidence := "1-Confirmed IOC" ;
    CommandLine=/\/tn\s+.?SysMon/iF | Indicator := "SysMon scheduled task" | Confidence := "2-High" ;
    CommandLine=/-R\s+.?\*:0:localhost:22/iF | Indicator := "Reverse SSH tunnel to local :22" | Confidence := "2-High" ;
    CommandLine=/autossh\s.*-M\s+0/iF | Indicator := "autossh tunnel, monitor disabled" | Confidence := "3-Medium" ;
    CommandLine=/setremotelogin\s+on/iF | Indicator := "macOS Remote Login enabled" | Confidence := "3-Medium" ;
    CommandLine=/OpenSSH\.Server/iF | Indicator := "Windows OpenSSH Server install" | Confidence := "3-Medium" ;
  }
| case {
    ParentBaseFileName=/^(cursor|code|electron|node)/iF | SpawnedByEditor := "yes" ;
    * | SpawnedByEditor := "no" ;
  }
| groupBy([aid, Confidence, Indicator, SpawnedByEditor],
    function=[count(as=Executions),
              min(@timestamp, as=FirstSeen),
              max(@timestamp, as=LastSeen),
              collect([UserName, ParentBaseFileName], limit=10),
              selectLast([CommandLine, TargetProcessId])],
    limit=max)
| match(file="aid_master_main.csv", field=[aid], column=aid, include=[ComputerName], strict=false)
| ProcessExplorer := format("[Process Explorer](https://falcon.crowdstrike.com/investigate/process-explorer/%s/%s)", field=[aid, TargetProcessId])
| sort(Confidence, order=asc, limit=1000)
| formatTime(format="%F %T %Z", field=FirstSeen, as=FirstSeen)
| formatTime(format="%F %T %Z", field=LastSeen, as=LastSeen)
| table([ComputerName, aid, Confidence, Indicator, SpawnedByEditor, UserName, ParentBaseFileName, Executions, FirstSeen, LastSeen, CommandLine, ProcessExplorer], limit=1000)

// ================= h5_hashes.cql =================
defineTable(
    name="ioc_hashes",
    query={
      createEvents([
        "ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15;Malicious extension.js (all four VSIXs)",
        "fcbb327e38e61c4fec795e0d0591f52cd1014b813d20a5912104953c3a17c364;Malicious VSIX 2.1.312 darwin-arm64",
        "3de1722901165769893bef57c72594e9a54459faa23f3091b136b79966edd081;Malicious VSIX 2.1.312 win32-x64",
        "80402fdcad8799285fd93044976973ca000da7995fb93363f819bb8e4f84ee6c;Malicious VSIX 2.1.313 darwin-arm64",
        "6786ec90cbd45949695bd7805c9fbb26cfc91bc5fc897de0183d9bcb9cb21731;Malicious VSIX 2.1.313 win32-x64",
        "22f682d9ff55264e934d0f43fcfbb46d58be5cfb8fe1b3a7cbb38fe089c818b0;Dropped smt.cmd (Windows persistence)",
        "7e0a52885fadee05544a9e99eb18c792bec05900a5e1a66d68f8383decb0e278;Dropped tunnel private key (.stk_/.smtk)",
        "49d616941deb44840dc89061c617ad7a325aa32113819ddc14e9c8dc238c83d1;Post-implant authorized_keys (sandbox-specific)"
      ])
      | @rawstring=/^(?<ioc_hash>[0-9a-f]{64});(?<ioc_desc>.+)$/
    },
    include=[ioc_hash, ioc_desc]
  )
// Hunt 5 - Any Falcon event carrying a published SHA-256
| #repo=base_sensor SHA256HashData=*
| match(file="ioc_hashes", field=[SHA256HashData], column=ioc_hash, include=[ioc_desc], ignoreCase=true)
| groupBy([aid, ioc_desc, SHA256HashData],
    function=[count(as=Events),
              min(@timestamp, as=FirstSeen),
              max(@timestamp, as=LastSeen),
              collect([#event_simpleName], limit=10),
              selectLast([TargetFileName, ImageFileName])],
    limit=max)
| match(file="aid_master_main.csv", field=[aid], column=aid, include=[ComputerName], strict=false)
| formatTime(format="%F %T %Z", field=FirstSeen, as=FirstSeen)
| formatTime(format="%F %T %Z", field=LastSeen, as=LastSeen)
| table([ComputerName, aid, ioc_desc, SHA256HashData, "#event_simpleName", TargetFileName, ImageFileName, Events, FirstSeen, LastSeen], limit=1000)

// ================= h6_artifacts.cql =================
// Hunt 6 - Persistence scripts, tunnel keys, LaunchAgent, Startup fallback, authorized_keys writes
#event_simpleName=*Written
// Intentional: no * fall-through - drop writes that match no artifact
| case {
    TargetFileName=/LaunchAgents[\\\/]com\.apple\.sysmond\.plist$/iF | Artifact := "macOS LaunchAgent com.apple.sysmond" ;
    TargetFileName=/Startup[\\\/]sysmon\.cmd$/iF | Artifact := "Windows Startup sysmon.cmd fallback" ;
    TargetFileName=/\.config[\\\/](\.smt|smt\.cmd)$/iF | Artifact := "Tunnel retry script (.smt / smt.cmd)" ;
    TargetFileName=/\.config[\\\/]\.?smtk$/iF | Artifact := "Persistent tunnel key (.smtk / smtk)" ;
    TargetFileName=/[\\\/]\.stk_[0-9a-f]{10}$/iF | Artifact := "Temp tunnel key (.stk_<10 hex>)" ;
    TargetFileName=/[\\\/]\.ssh[\\\/](administrators_)?authorized_keys$/iF | Artifact := "authorized_keys written (verify writer)" ;
  }
| groupBy([aid, Artifact],
    function=[count(as=Writes),
              min(@timestamp, as=FirstSeen),
              max(@timestamp, as=LastSeen),
              collect([#event_simpleName], limit=5),
              selectLast([TargetFileName, ContextProcessId, SHA256HashData])],
    limit=max)
| match(file="aid_master_main.csv", field=[aid], column=aid, include=[ComputerName], strict=false)
| WriterProcess := format("[Process Explorer](https://falcon.crowdstrike.com/investigate/process-explorer/%s/%s)", field=[aid, ContextProcessId])
| sort(LastSeen, order=desc, limit=1000)
| formatTime(format="%F %T %Z", field=FirstSeen, as=FirstSeen)
| formatTime(format="%F %T %Z", field=LastSeen, as=LastSeen)
| table([ComputerName, aid, Artifact, TargetFileName, SHA256HashData, Writes, FirstSeen, LastSeen, WriterProcess], limit=1000)

// ================= h7_schtask.cql =================
// Hunt 7 - Windows SysMon scheduled task (requests SYSTEM, runs smt.cmd)
#event_simpleName=ScheduledTaskRegistered
// Intentional: no * fall-through
| case {
    TaskName=/(^|\\)SysMon$/iF | Indicator := "Task name SysMon" ;
    TaskExecCommand=/smt\.cmd/iF | Indicator := "Task action runs smt.cmd" ;
    TaskExecArguments=/smt\.cmd/iF | Indicator := "Task arguments reference smt.cmd" ;
  }
| groupBy([aid, TaskName, Indicator],
    function=[count(as=Registrations),
              min(@timestamp, as=FirstSeen),
              max(@timestamp, as=LastSeen),
              selectLast([TaskExecCommand, TaskExecArguments, TaskAuthorUserName, UserName])],
    limit=max)
| match(file="aid_master_main.csv", field=[aid], column=aid, include=[ComputerName], strict=false)
| formatTime(format="%F %T %Z", field=FirstSeen, as=FirstSeen)
| formatTime(format="%F %T %Z", field=LastSeen, as=LastSeen)
| table([ComputerName, aid, TaskName, Indicator, TaskExecCommand, TaskExecArguments, TaskAuthorUserName, UserName, Registrations, FirstSeen, LastSeen], limit=1000)

// ================= h8_inbound_ssh.cql =================
// Hunt 8 - Follow-on access: processes spawned by an SSH server on endpoints
#event_simpleName=ProcessRollup2
| in(field=ParentBaseFileName, values=["sshd", "sshd.exe", "sshd-session", "sshd-auth"], ignoreCase=true)
| groupBy([aid, UserName, FileName],
    function=[count(as=Spawns),
              min(@timestamp, as=FirstSeen),
              max(@timestamp, as=LastSeen),
              collect([CommandLine], limit=5)],
    limit=max)
| match(file="aid_master_main.csv", field=[aid], column=aid, include=[ComputerName], strict=false)
| sort(LastSeen, order=desc, limit=1000)
| formatTime(format="%F %T %Z", field=FirstSeen, as=FirstSeen)
| formatTime(format="%F %T %Z", field=LastSeen, as=LastSeen)
| table([ComputerName, aid, UserName, FileName, Spawns, FirstSeen, LastSeen, CommandLine], limit=1000)
