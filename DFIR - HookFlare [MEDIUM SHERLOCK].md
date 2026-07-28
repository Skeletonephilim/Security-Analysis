
Date : 12/07/2026

A S1rBank client reported unauthorized transactions. The victim received an SMS urging a banking app update via a link, which installed a dormant app mimicking the bank's official version. Once activated, it stole credentials, bypassed 2FA via SMS interception, and exfiltrated data.

Evidence is `HookFlare.zip` containing `HookFlare.dd` (Android-x86 9.0 ext4, ~2.1 GB) and `HookFlare.pcap` (~72 KB). We'll work the disk for victim artifacts, MobSF for the APK, and the pcap for exfil.

```bash
> cd /Users/satanael/HookFlare_case/evidence
> unzip -P hacktheblue /Users/satanael/Downloads/HookFlare.zip
> fsstat HookFlare.dd | head -10
FILE SYSTEM INFORMATION
File System Type: Ext4
Volume Name: Android-x86
Last Mounted at: 2025-02-01 17:06:31 (CET)
```

Single ext4 filesystem, no partition table — mounted path was `/data`.

MobSF on the MacBook for static APK analysis :

```bash
python3 -c "import json; p='$HOME/.docker/config.json'; d=json.load(open(p)); d.pop('credsStore',None); json.dump(d,open(p,'w'),indent=2)"

bash /Users/satanael/HookFlare_case/setup_lab.sh
```

```bash
> colima start --cpu 2 --memory 4 --disk 20
> docker run -d --name mobsf-hookflare \
  -p 127.0.0.1:8000:8000 \
  -v /Users/satanael/HookFlare_case/work:/home/mobsf/uploads:ro \
  opensecurity/mobile-security-framework-mobsf:latest
```

```bash
793e22b19422: Pull complete
Digest: sha256:fc6a70b6a62ad406cc8941209c6ba0fde257c655457b536ad0ca3445a792f256
Status: Downloaded newer image for opensecurity/mobile-security-framework-mobsf:latest
docker.io/opensecurity/mobile-security-framework-mobsf:latest
[*] Starting MobSF on http://127.0.0.1:8000 (host-only, no outbound from container by default)
3091f13d14d6fc6f09b6802b157a2a26605bba34a0128c8aa561fc3118f8eb57
```

Login `mobsf` / `mobsf` at http://127.0.0.1:8000 — upload `S1rBank.apk`.

MobSF surfaces the weapon :

`com/s1rx58/s1rbank/MyBackgroundService.java` → package `com.s1rx58.s1rbank`

`http://s1rbank.net:80/api/data` → primary C2 / exfil

`https://discord.com/api/webhooks/1334648260610097303/-Lkxr0eZRO_fb_SaumBbBMZyANM3lyeCkR-E1NXXRASPbtRdNksQSzx4pY1ZGQkFR2H8` → fallback if primary is down

`secretsE1NXXRASPbtRdNksQSzx4pY1ZGQkFR2H8` → possible hardcoded secret

`B/h.java` → `SecretKeySpec` AES key + Discord fallback in `i0()`

`MyBackgroundService.java` → `HEAD` health-check then `POST` with `Data-Type: payment|sms|call_log`

`http://schemas.android.com/apk/res/android` is normal manifest noise, not an IoC.

Discord as backup exfil is common on commodity mobile trojans — no dedicated C2 to maintain if `s1rbank.net` gets burned.

MobSF won't ingest `.db` files ; SMS lives on the disk image. `tsk_recover` pulled 2375 files but the recovered `mmssms.db` was corrupt — XML had overwritten the SQLite header. We carve the live inode instead :

```bash
> fls -r -p HookFlare.dd | rg "mmssms.db$"
> icat HookFlare.dd 110250 > ../work/mmssms_real.db
> xxd ../work/mmssms_real.db | head -1
00000000: 5351 4c69 7465 2066 6f72 6d61 7420 3300  SQLite format 3.
```

Phishing SMS :

```bash
> sqlite3 -separator ' | ' ../work/mmssms_real.db \
"SELECT _id, datetime(date/1000,'unixepoch') AS utc_time, address, body
 FROM sms
 WHERE body LIKE '%s1rbank%' OR body LIKE '%update your app%';"

25 | 2025-02-01 16:20:32 | 14356951192 | S1rBank Alert: We detected a paid process of $700.00 (Ref #971253158RS) on your account. To confirm this transaction, please update your app now: s1rbank.net/app Call +1 (505) 695-1110 for assistance.
```

`date` is epoch milliseconds — divide by 1000 for UTC → `2025-02-01 16:20:32`.

`downloads.db` `lastmod` gave `2025-02-01 17:03:25` but HTB rejected it ; that's last row update near completion, not download start. Chrome `History` → `downloads.start_time` gives `2025-02-01 17:03:23`.

Runtime permissions for `com.s1rx58.s1rbank` :

```bash
> rg -A6 'name="com.s1rx58.s1rbank"' ../extracted/android-9.0-r2/data/system/users/0/runtime-permissions.xml
```

Four granted : `READ_SMS`, `READ_CALL_LOG`, `READ_EXTERNAL_STORAGE`, `WRITE_EXTERNAL_STORAGE`.

READ_SMS last access — `appops.xml`, op code `14`, `tt="1738429638041"` → `2025-02-01 17:07:18` UTC.

Exfil on the wire :

```bash
> tshark -r HookFlare.pcap -Y "http.request" -T fields \
  -e frame.time_utc -e http.request.method -e http.host -e http.request.uri
```

`HEAD` then `POST` to `s1rbank.net/api/data` at 17:07:18 UTC. POST bodies are Base64-wrapped AES ciphertext ; key from `B/h.java`.

```bash
❯ python3 /Users/satanael/HookFlare_case/work/decrypt_exfil.py
=== payment (frame 127) ===
Full Name: PHILLIP KEELING
Card Number: 5453004085527987
Expiration Date: 05/27
CVV: 185

  line 1: Full Name: PHILLIP KEELING
  line 2: Card Number: 5453004085527987
  line 3: Expiration Date: 05/27
  line 4: CVV: 185

=== sms (frame 137) ===
From: 14356951192
Message: S1rBank Alert: We detected a paid process of $700.00 (Ref #971253158RS) on your account. To confirm this transaction, please update your app now: s1rbank.net/app Call +1 (505) 695-1110 for assistance.

From: 12178627958
Message: Hi Phillip

From: 12178627958
Message: Hi Phillip

From: 2125484568
Message: HELLO

From: 12049678533
Message: Hello


  line 1: From: 14356951192
  line 2: Message: S1rBank Alert: We detected a paid process of $700.00 (Ref #971253158RS) on your account. To confirm this transaction, please update your app now: s1rbank.net/app Call +1 (505) 695-1110 for assistance.
  line 3: 
  line 4: From: 12178627958
  line 5: Message: Hi Phillip
  line 6: 
  line 7: From: 12178627958
  line 8: Message: Hi Phillip
  line 9: 
  line 10: From: 2125484568
  line 11: Message: HELLO
  line 12: 
  line 13: From: 12049678533
  line 14: Message: Hello
  line 15: 

=== call_log (frame 146) ===
```

Frame 127 is `Data-Type: payment` — second line is `Card Number: 5453004085527987`. Victim name matches the SMS thread (`Hi Phillip`).

```bash
> docker stop mobsf-hookflare
> docker rm mobsf-hookflare
```
