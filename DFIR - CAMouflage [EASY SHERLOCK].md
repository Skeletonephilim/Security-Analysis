Date : 30/07/2026

Sherlock : CAMouflage (DFIR / KAPE triage)

.zip : `CAMouflage.zip` → nested KAPE `2025-06-21T205150_output.zip` — password : `hacktheblue`

"A newly launched campaign has been detected targeting multiple users utilizing cracked applications…" — triage laptop, dig root cause / extent.

```bash
> 7z x -p'hacktheblue' CAMouflage.zip -oCAMouflage-analysis -y
> 7z x -p'hacktheblue' CAMouflage-analysis/2025-06-21T205150_output.zip -oCAMouflage-analysis/triage -y
> export C=~/Downloads/CAMouflage-analysis/triage/C
```

`KAPE : Kroll Artifact Parser and Extractor` face: `C/` ≈ victim volume. Scenario points at a cracked-app installer — start in Prefetch / `BAM`, not random EVTX grepping.

Initial access — cracked installer runs

A parser reads a binary format and emits fields (name, run count, timestamps). Win10 Prefetch is `MAM`-compressed; Arch’s stock `prefetch` CLI dies on that. `pyscca` (`python-libscca-python`) via portable CPython 3.12 is the translator.

```bash
> ls "$C/Windows/prefetch" | rg -i 'master|crack'
# DOWNLOAD MASTERCAM X9 FULL CR-C7EFFD46.pf

> PY312=~/Downloads/CAMouflage-analysis/tools/python/bin/python3.12
> $PY312 - <<'PY'
import sys
sys.path.insert(0, "/usr/lib/python3.12/site-packages")
import pyscca
pf = pyscca.open("/home/vagabond/Downloads/CAMouflage-analysis/triage/C/Windows/prefetch/DOWNLOAD MASTERCAM X9 FULL CR-C7EFFD46.pf")
print("exe:", pf.get_executable_filename())
print("run_count:", pf.get_run_count())
times = [t for i in range(8) if (t := pf.get_last_run_time(i)).year > 1601]
print("FIRST:", min(times))
print("LAST start:", max(times))
PY
```

`run_count: 2`. Oldest stamp = first launch of `download mastercam x9 full crack pc.exe` → `2025-06-21 18:34:19`.

`ATT&CK ID : User Execution - Malicious File T1204.002`
`ATT&CK ID : Masquerading - cracked legitimate software lure T1036`

Installer lifespan end — BAM (not Prefetch mtime)

Prefetch run entries are starts. `.pf` Modified from CopyLog (`18:35:58`) is a flush — not process end. `BAM : Background Activity Moderator` (`SYSTEM\...\bam\State\UserSettings\<SID>`) keeps last-activity FILETIME per image path → installer `2025-06-21 18:36:52`. Sibling `extrac32.exe` (real SysWOW64 `LOLBin : Living-off-the-Land Binary`) lands around `18:36:04` for `.cab` unpack — not a patched mock binary.

`ATT&CK ID : (host artifact) BAM last binary activity — closes installer window when 4689 is absent`

First durable drop — `USN : Update Sequence Number` (`$J`) after execute

Right after `18:34:19`:

```bash
> rg '2025-06-21 18:34:2' ~/Downloads/CAMouflage-analysis/ez-out/usn.csv | rg FILE_CREATE | head

13074040,,USN_REASON_FILE_CREATE,562949953518446,281474976808991,2025-06-21 18:34:22.231640,nsv52EF.tmp,
13074128,,USN_REASON_FILE_CREATE | USN_REASON_CLOSE,562949953518446,281474976808991,2025-06-21 18:34:22.231640,nsv52EF.tmp,
13074304,,USN_REASON_FILE_CREATE,844424930229102,281474976808991,2025-06-21 18:34:25.511586,Mysql.wp5,/Users/Administrator/AppData/Local/Temp/Mysql.wp5
13074432,,USN_REASON_DATA_EXTEND | USN_REASON_FILE_CREATE,844424930229102,281474976808991,2025-06-21 18:34:25.527548,Mysql.wp5,/Users/Administrator/AppData/Local/Temp/Mysql.wp5
13074512,,USN_REASON_DATA_EXTEND | USN_REASON_FILE_CREATE | USN_REASON_CLOSE,844424930229102,281474976808991,2025-06-21 18:34:25.527548,Mysql.wp5,/Users/Administrator/AppData/Local/Temp/Mysql.wp5
13074592,,USN_REASON_FILE_CREATE,844424930230073,281474976808991,2025-06-21 18:34:25.527548,Authorization.wp5,/Users/Administrator/AppData/Local/Temp/Authorization.wp5
13074688,,USN_REASON_DATA_EXTEND | USN_REASON_FILE_CREATE,844424930230073,281474976808991,2025-06-21 18:34:25.543572,Authorization.wp5,/Users/Administrator/AppData/Local/Temp/Authorization.wp5
13074784,,USN_REASON_DATA_EXTEND | USN_REASON_FILE_CREATE | USN_REASON_CLOSE,844424930230073,281474976808991,2025-06-21 18:34:25.543572,Authorization.wp5,/Users/Administrator/AppData/Local/Temp/Authorization.wp5
13074880,,USN_REASON_FILE_CREATE,1125899906941498,281474976808991,2025-06-21 18:34:25.558696,Lock.wp5,/Users/Administrator/AppData/Local/Temp/Lock.wp5
13074960,,USN_REASON_DATA_EXTEND | USN_REASON_FILE_CREATE,1125899906941498,281474976808991,2025-06-21 18:34:25.558696,Lock.wp5,/Users/Administrator/AppData/Local/Temp/Lock.wp5
```

`nsv52EF.tmp` is `NSIS : Nullsoft Scriptable Install System` bootstrap noise (create+delete same tick — installer plumbing). Board wants the first **kept** staged payload: `Mysql.wp5` under `%Temp%` (`C:\Users\Administrator\AppData\Local\Temp\Mysql.wp5`). Name is decoy — file is obfuscated script text (`Set …=` + junk English tokens), not MySQL/SQL. `.wp5` = fake extension (masquerade), same family as sibling `Authorization.wp5` / `Lock.wp5` / …

`ATT&CK ID : Masquerading - Match Legitimate Name or Location / Double Extension-class decoy T1036`
`ATT&CK ID : Obfuscated Files or Information T1027`

---

CAB unpack — `extrac32` LOLBin (args live in the script, not Prefetch)

Prefetch proves `extrac32.exe` ran; it never stores the command line. Deobfuscate `%Temp%\Mysql.wp5` (batch `Set` + junk tokens → expand `%var%`):

```bash
> python3 deob_mysql.py   # expand Set Ten=5 … then %Stopping%→o etc.
# extrac32 /Y Play.wp5 *.*
```

`/Y` = overwrite without prompt; `*.*` = every member of the cabinet (`Play.wp5`).

`MITRE ID : Command and Scripting Interpreter - Windows Command Shell T1059.003`
`MITRE ID : System Binary Proxy Execution / LOLBin extrac32 T1218`

AV/EDR process recon — `tasklist | findstr`

Same deob shows two live checks before unpack:

```text
tasklist | findstr /I "opssvc wrsa"
tasklist | findstr "bdservicehost SophosHealth AvastUI AVGUI nsWscSvc ekrn"
```

Eight security-product process strings (CrowdStrike / Webroot / Bitdefender / Sophos / Avast / AVG / Norton / ESET). Hit on the first pair delays with `ping -n 192 127.0.0.1`; hit on the second retargets the runner name to `AutoIt3.exe` + `.a3x`.

`MITRE ID : Security Software Discovery T1518.001`

Batch → renamed AutoIt host

Script builds `%Temp%\448887\Moscow.com` (`copy /b` PE fragments from the cab), appends compiled script as `K`, then `start Moscow.com K`. Prefetch `MOSCOW.COM-34B22CCB.pf` maps both `...\448887\MOSCOW.COM` and `...\448887\K`. Version info on `Moscow.com`: `OriginalFilename = AutoIt3.exe`.

```bash
> sha256sum "$TEMP/448887/Moscow.com"
# 1300262a9d6bb6fcbefc0d299cce194435790e70b9c7b4a651e202e90a32fd49   # host image
> cat Runner.wp5 Art.wp5 Gba.wp5 Romania.wp5 Refugees.wp5 Authorization.wp5 Lock.wp5 | sha256sum
# 2b3d1561b9ae7fa2bd3f09dee28a327b5647a908113945cd2a943134822d18d0   # K (loaded script)
```

Process name after the batch: `Moscow.com`. Original name: `AutoIt3.exe`. File loaded by that process: `K` → SHA-256 `2b3d1561b9ae7fa2bd3f09dee28a327b5647a908113945cd2a943134822d18d0`.

`MITRE ID : Masquerading - Match Legitimate Name or Location T1036.005`
`MITRE ID : Process Injection (AutoIt → explorer hollow later in script) T1055`

Delivery host vs C2 — two different things

Edge History shows the lure zip pulled from `media.cloud839v1.cfd` via a `fancli.com` redirect. That is **staging/delivery**, not command-and-control: the download happened at `16:41`, twenty minutes before the installer ever ran, and it is browser-attributed, not payload-attributed.

```bash
> sqlite3 -readonly "file:$EDGE/History?immutable=1" \
  "SELECT datetime(last_visit_time/1000000-11644473600,'unixepoch'), url FROM urls WHERE url LIKE '%.cfd%';"
# 2025-06-21 16:41:09 | https://media.cloud839v1.cfd/Download+Mastercam+X9+Full+Crack+Pc.zip
```

`MITRE ID : Stage Capabilities - Upload Malware T1608.001`
`MITRE ID : Ingress Tool Transfer T1105`

C2 domain — recovered from the injected stealer, not from triage

No triage artifact holds the C2. There is no `pcap`, no Sysmon, no DNS Client operational log, `SRUDB.dat` records bytes and not hostnames, and `WebCacheV01.dat` only holds Edge/OCSP traffic. The `Moscow.com` Prefetch does map `WININET.DLL`, `DNSAPI.DLL` and `WS2_32.DLL`, which proves the AutoIt host resolved and spoke HTTP — but Prefetch never stores the name it resolved.

So the answer has to come out of the payload. The AutoIt script `K` decrypts an `RC4`-wrapped, `LZNT1`-compressed PE and injects it into `explorer.exe`. That PE imports nothing network-related (`KERNEL32`, `GDI32`, `USER32`, `ole32` only — clipboard grab, `BitBlt` screenshots, `WMI` via `CoSetProxyBlanket`), because it resolves every API by hash at runtime and builds every string inside a decoder function. Static `strings` on it returns zero domains, and the file has no high-entropy region, so there is no monolithic encrypted config blob to attack either.

`FLOSS : FireEye Labs Obfuscated String Solver` emulates each decoder function and captures what it writes:

```bash
> floss -n 5 --color never lumma_payload.bin
# FLOSS DECODED STRINGS (15)
# Lcrowfza.xyz/gkaj
# gewgb.xyz/axgh
# - LummaC2 Build: Jun 16 2025
# # Buy now: TG @lummanowork
# SELECT * FROM AntiVirusProduct
```

Family and build date come out in the same pass: `LummaC2`, built `Jun 16 2025`, five days before execution. The leading `L` on the first entry is an emulation artefact, confirmed because `lcrowfza.xyz` has zero threat-intel presence while `crowfza.xyz` is tracked as Lumma C2:

```bash
> curl -s "https://otx.alienvault.com/api/v1/indicators/domain/crowfza.xyz/general" | jq '.pulse_info.count'
# 6   -> "Lumma Stealer C2 Infra", "Mapping latest Lumma infrastructure", 144.172.115.212
```

C2 domain : `crowfza.xyz` (`https://crowfza.xyz/gkaj`), with `gewgb.xyz/axgh` as the fallback in the same config.

`MITRE ID : Application Layer Protocol - Web Protocols T1071.001`
`MITRE ID : Deobfuscate/Decode Files or Information T1140`
`MITRE ID : Obfuscated Files or Information - Software Packing T1027.002`
`MITRE ID : Process Injection T1055`
`MITRE ID : Security Software Discovery T1518.001`

**Blue Team :** Hunt `extrac32` + odd cab names (`Play.wp5`), `tasklist|findstr` with AV process lists, and AutoIt hosts renamed to `*.com` under `%Temp%\<digits>\`. Prefetch mapped files for `Moscow.com` → `K` is enough to hash the loaded script even after `K` is deleted. Edge downloads of `*.cfd` crack mirrors are the early IOC for the same campaign. The gap this case exposes is network telemetry: with no Sysmon Event ID 22 and no DNS Client operational log, `crowfza.xyz` was unrecoverable from host artefacts and had to be reversed out of injected code — one `Sysmon` DNS rule would have made it a five-second query.

**Purple Team :** The delivery host and the C2 belong to different stages and different ATT&CK tactics. `media.cloud839v1.cfd` is Resource Development and browser-attributed; `crowfza.xyz` is Command and Control and lives only inside injected memory. Treating the first as the C2 is the trap this Sherlock is built around, and it is the same trap in production triage — the loudest domain in browser history is rarely the one the implant talks to.

**Purple Team :** Operator stacked decoys: fake `.wp5` extensions, English-token batch obfuscation, signed-looking AutoIt renamed `Moscow.com`, cab members as PE fragments, and AV-aware branching (sleep vs rename to `AutoIt3.exe`) so sandbox/EDR fingerprints shift. Prefetch has no cmdline — Blue must recover args from the dropped script or miss `/Y Play.wp5 *.*`.
