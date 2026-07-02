
Date : 28/06/2026

This is the `blue team` mirror of the `Bruno [MEDIUM].md` Black-Box that can be found in my `HTB-Black-Box` repository.

Important split:

`prevent` = make the attack hard or impossible before it starts
`detect` = see it while it happens and respond

Different roles, different timing.

Who would've prevented or mitigated my AD chain :

`Security Engineer / AD Architect`

Why:

they harden `identity`, which is the core of AD attacks
they can remove unnecessary `SPN`s (reduces kerberoast surface)
they can enforce `gMSA` for service accounts
they can restrict dangerous delegation patterns before you exploit them

Who detects first during attack (hunt lane):

`Threat Hunter / Detection Engineer`

Why:

they search for attacker behavior even when no alert fired yet
they correlate auth and identity anomalies (`Kerberos`, new computer accounts, delegation changes)
they investigate suspicious tickets and identity graph changes proactively

Bruno chain with likely stop points in order:

1) `Anonymous FTP` on `21/tcp` exposing `SampleScanner` binaries
- prevent: disable anonymous FTP or isolate app share
- detect: FTP auth/file access monitoring, suspicious binary retrieval

2) static analysis leakage (`strings`, changelog, runtime config) -> `svc_scan` discovery
- prevent: no sensitive cred material in deploy artifacts
- detect: heavy outbound transfer of app binaries from DC FTP

3) `AS-REP roasting` on `svc_scan` (`DONT_REQUIRE_PREAUTH` style weakness)
- prevent: enable preauth, remove vulnerable account config
- detect: `4768` anomalies, AS-REP volume alerts, crackable ticket patterns

4) writable `queue` share + zip-slip write primitive
- prevent: tight share ACLs, path canonicalization in app, deny dangerous archive extraction paths
- detect: suspicious archive upload + DLL write into app directory

5) callback from `queue` automation (`nc` / reverse shell)
- prevent: egress filtering, app sandboxing, no arbitrary outbound from scanner service context
- detect: new outbound connection from server process, EDR process lineage alerts

6) `MAQ` abuse + new machine account (`scrowpc$`)
- prevent: set `ms-DS-MachineAccountQuota` to `0` for non-admin tiers
- detect: new computer object creation alerts, unusual `$` account enrollment

7) `KrbRelay` + `RBCD` graft on `BRUNODC$`
- prevent: harden LDAP signing/channel binding, reduce coercion exposure, delegation review
- detect: directory change on `msDS-AllowedToActOnBehalfOfOtherIdentity` (often `5136`), suspicious Kerberos S4U usage

8) `getST` / S4U replay to admin context
- detect: anomalous S4U ticket requests, impossible source/target pairings, tier-violation auth patterns

9) pass-the-ticket / `psexec.py -k -no-pass` to `SYSTEM`
- detect: privileged logon anomalies (`4624` context), lateral admin auth from unexpected principal

What usually stops operators in real life vs HTB:

In HTB, many controls are intentionally weak so the chain is learnable.
In production, steps `1-5` are where mature teams most often catch less disciplined operators.
Steps `6-8` are where strong AD teams catch skilled operators if hunting is active.

If IR only resets `svc_scan` password, but misses `scrowpc$` and RBCD graft, access can survive through machine identity and delegation.
That is a hunter/architect problem, not just password reset.
