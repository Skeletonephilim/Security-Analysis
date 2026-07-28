Target : HTB Sherlock FortySeven-1

Date : 29/06/2026

This is not a shell box.
This is a `Threat Intelligence` Sherlock on `HackTheBox`.
The work is reading vendor reports, merging naming splits, and answering precise questions from evidence text.

We'll use three primary sources:

`https://securelist.com/mysterious-elephant-apt-ttps-and-tools/117596/`
`https://medium.com/@knownsec404team/apt-k-47-mysterious-elephant-a-new-apt-organization-in-south-asia-5c66f954477`
`https://medium.com/@knownsec404team/apt-k-47-mysterious-elephant-a-new-apt-organization-in-south-asia-5c66f954477` (Asyncshell / Hajj lure branch)

First job was actor alignment.

`Kaspersky` calls the set `Mysterious Elephant`.
`Knownsec` calls the same family `APT-K-47`.
Different vendor labels, same tooling lineage, same South Asia campaign context.

Campaign shape from the reports:

`Hajj`-themed phishing against government and diplomatic targets
collection and theft oriented around `WhatsApp` data
loader/backdoor chain with multiple staged tools

We'll map the chain in operator order, not MITRE decoration first:

initial access -> phishing lure
execution -> `BabShell` / script execution path
persistence -> startup or autorun style behavior
collection -> browser credential theft (`ChromeStealer` family behavior in reporting)
exfiltration -> `WhatsApp`-focused theft tooling

Important tools named across sources:

`BabShell`
`MemLoader HidenDesk` (hidden desktop execution)
`ORPCBackdoor`
`Asyncshell` (`v1` through `v4` evolution)
`CVE-2023-38831` in lure context (WinRAR-style archive abuse class)

Evidence pass 1 (Kaspersky):

tool names, IoCs, loader behavior, exfil focus
`MemLoader HidenDesk` sandbox and environment assumptions

Evidence pass 2 (Knownsec):

`ORPCBackdoor` details
homology notes tying tooling families together

Evidence pass 3 (Knownsec Asyncshell branch):

`Asyncshell` version lineage
Hajj lure mechanics
`CVE-2023-38831` reference for archive-based delivery

We'll hunt in-page instead of trusting memory.

```bash
>  curl -s 'https://securelist.com/mysterious-elephant-apt-ttps-and-tools/117596/' | w3m -dump -T text/html | grep -i 'whatsappob\|md5\|hiddendesk\|mysterious elephant' | head
```

```bash
>  curl -s 'https://medium.com/@knownsec404team/apt-k-47-mysterious-elephant-a-new-apt-organization-in-south-asia-5c66f954477' | w3m -dump -T text/html | grep -i 'asyncshell\|orpc\|hajj\|cve-2023-38831' | head
```

MITRE mapping used in answers:

`T1059.001` -> PowerShell or script execution behavior in the chain
`T1547.001` -> persistence via startup folder / run key class behavior
`T1041` -> exfiltration over existing command channel

Sandbox evasion reasoning from reports:

malware checks running process count
sparse analysis VMs may look "too empty"
malware may refuse to execute in that environment

```text
if running_processes < threshold:
    exit early
else:
    continue infection chain
```

That is environment gating, not proof of benign intent.

IR vocabulary was the hardest part, not Ctrl+F.

We forced clean definitions:

false positive -> the alert or classification is wrong
true positive (file) -> hash or signature matches malicious content on disk
quarantine -> detection succeeded and remediation happened
no execution yet -> still not the same as "safe" or "false positive"

Best question from the session:

if hash matches known malware on disk, how is that a false positive?

Answer shape:

it is not a false positive for malicious file presence
execution and exfil are separate downstream stages
defender still has an incident even if outbound exfil never occurred

Hash reasoning used in room:

hash fingerprints file content, not filename
rename does not change hash
dormant file on disk still matches the same hash
MD5 collision theory exists, but IR default is content match unless you have collision proof

IoC work example:

sample name `WhatsAppOB.exe`
hash lookup from report tables -> `<REDACTED_MD5_WHATSAPPOB>`

Sensitive task outputs redacted here:

`<REDACTED_TASK_ANSWERS>`
`<REDACTED_MD5_WHATSAPPOB>`
`<REDACTED_CVE_ANSWER>`

Scars:

`F47-S1`: false positive confused with dormancy / no WhatsApp installed / phish-only presence
`F47-S2`: Defender quarantine read as "not malware"
`F47-S3`: CVE submission rejected on unicode dash — use ASCII `CVE-2023-38831`
`F47-S4`: hash is content fingerprint, not byte counter

Retired hypotheses:

different vendor names mean different actors -> retired after tool/timeline overlap
sandbox refusal means sample is benign -> retired
quarantine equals false positive -> retired

Comprehension verdict:

First defensive TI rep where argument quality mattered more than exploit speed.
Strong Q3/Q4 push on detection vs impact.
Next paired rep should add PCAP or log artifacts, not report reading alone.
