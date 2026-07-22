
Date : 22/07/2026

Our SOC detected an emerging RAT variant delivered via malicious file execution in its early stages, triggering an alert before C2 communication was fully established. Rapid containment prevented further exfiltration or post-exploitation activities. A full forensic triage was conducted to analyze persistence mechanisms and C2 infrastructure, enabling comprehensive IOC extraction to provide them to our threat intelligence platform for enhanced detection and proactive hunting.

Evidence is `Kraken.zip` (password `hacktheblue`) → single file `Evidence.ad1` (~283 MB), an FTK Imager logical/custom content image of a Windows host (`Administrator`). Sleuth Kit cannot open AD1, so we work from a Mac with `ad1-viewer` + `pyscca` (libscca) for Prefetch.

```bash
> cd /Users/satanael/Kraken_case/evidence
> unzip -P hacktheblue /Users/satanael/Downloads/Kraken.zip
> ls -la
Evidence.ad1
> file Evidence.ad1
Evidence.ad1: data
```

We dump the AD1 tree and pull Prefetch plus the lure / staged bats into `extracted/` :

```bash
> # ad1-viewer walk → evidence_tree.txt (888 dirs / 3979 files)
> # export C:\Windows\Prefetch\*.pf → extracted/Prefetch/
> # export Downloads\Art-.zip, Temp\temp_993805.bat, dwm.bat, Startup\5c74.bat
> pip3 install --user libscca-python dnfile pycryptodome
> ls extracted/Prefetch | wc -l
193
> unzip -l extracted/artifacts/Art-.zip
Archive:  extracted/artifacts/Art-.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
   114592  06-13-2025 14:36   Conf.js
   422063  08-26-2023 00:00   The_Art_Of_War.pdf
```

`The_Art_Of_War.pdf` is the decoy ; `Conf.js` is what the user executes. Prefetch is not a Mac folder — the AD1 already holds the copied `C:\Windows\Prefetch\*.pf` blobs. We parse them with `pyscca` :

```bash
> python3 - <<'PY'
import pyscca
f = pyscca.file()
f.open('extracted/Prefetch/WSCRIPT.EXE-3FF4D889.pf')
print('exe:', f.get_executable_filename())
print('last:', f.get_last_run_time(0))
for i in range(f.get_number_of_filenames()):
    p = f.get_filename(i)
    if 'CONF' in p.upper() or 'TEMP_' in p.upper():
        print(p)
f.close()
PY
exe: WSCRIPT.EXE
last: 2025-06-13 14:43:27.197375
\VOLUME{01db6e3ba9900280-9ea9af27}\USERS\ADMINISTRATOR\DOWNLOADS\CONF.JS
\VOLUME{01db6e3ba9900280-9ea9af27}\USERS\ADMINISTRATOR\APPDATA\LOCAL\TEMP\TEMP_993805.BAT
```

`7ZG.EXE` Prefetch at `2025-06-13 14:36:35` touches `ART-.ZIP` / `CONF.JS` first ; user execution of the JS is WSCRIPT at `2025-06-13 14:43:27`.

`Conf.js` is WSH JScript — ActiveX `FileSystemObject` + `WScript.Shell`. First write is a random bat under Temp, then it launches it hidden :

```bash
> head -n 5 extracted/artifacts/art_unzip/Conf.js
try {
    var xxopxvfr = new ActiveXObject('WScript.Shell');
    var rmolyhjl = new ActiveXObject('Scripting.FileSystemObject');
    var fxujsdfn = rmolyhjl.GetSpecialFolder(2) + '\\' + 'temp_' + Math.floor(Math.random() * 1000000) + '.bat';
    var lyebcvne = rmolyhjl.CreateTextFile(fxujsdfn, true);
```

On this host that file is `temp_993805.bat`. Same SHA-1 as `%USERPROFILE%\dwm.bat` and Startup `5c74.bat` — carbon copies, different placement. The bat copies itself to `dwm.bat` so the later PowerShell stage has a fixed path to re-read.

Inside the bat we recover a PowerShell command line that strips junk marker `zxa`, then an AMSI patcher from a `:::` Base64 comment. The 6-byte overwrite is `mov eax, 0 ; ret` :

```bash
> rg -n "0xb8|AmsiInitialize|optimizationData" extracted/artifacts/injection_code.ps1
$optimizationData = [byte[]](0xb8,0x0,0x00,0x00,0x00,0xC3)
```

`dwm.bat` also carries a `:: ` line with two AES-256-CBC + GZip blobs. PowerShell decrypts them with the bat-layer key and `Assembly.Load`s both .NET stages in memory — stub `xxxxguddma.tmp` then loader `uapnaeviuv.tmp` (PE metadata names ; the on-disk carrier for this stage is still `dwm.bat`).

```bash
> python3 - <<'PY'
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64, gzip, hashlib, re
key = base64.b64decode('ImocNEnUZbHBmaXIBtoy7X3HCr9QsCDJAUlkq43qYFg=')
iv  = base64.b64decode('WCpQVGqc+E4SNHfKYV5jVQ==')
bat = Path('extracted/artifacts/temp_993805.bat').read_text(errors='replace')
payload = None
for line in bat.splitlines():
    s = re.sub(r'%[A-Za-z0-9_]+%', '', line).strip()
    if s.startswith(':: ') and not s.startswith(':::'):
        payload = s[3:]; break
for i, part in enumerate(payload.split('\\')):
    pt = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(base64.b64decode(part)), 16)
    data = gzip.decompress(pt)
    print(i, data[:2], len(data), hashlib.sha1(data).hexdigest())
PY
0 b'MZ' 4096 339e27243df24f2b8979e78711e396698f4f47cc
1 b'MZ' 31232 0c4236fd5a8b2cd632da0c1e06444e0a95bb7cd3
```

PE0 is a tiny stub (not malicious alone). PE1 embeds an encrypted resource named `xxxxxxxxxxxxxxxxxxxxxxxxxxxx.exe` (28× `x`). Loader key/IV (comma between key and IV — the `/` in `/mA=` is part of the Base64 key) :

```bash
> python3 - <<'PY'
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64, gzip, hashlib, dnfile
key = base64.b64decode('ALWIGeOnxudniHR2K4CNZmnaEZffXt6zKsRFoAM2/mA=')
iv  = base64.b64decode('JXYbOTuuz3cErOl30kAKhw==')
ct  = bytes(dnfile.dnPE('extracted/artifacts/stage_pe_1.bin').net.resources[0].data)
print('resource:', dnfile.dnPE('extracted/artifacts/stage_pe_1.bin').net.resources[0].name)
pt  = gzip.decompress(unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16))
print(pt[:2], len(pt), hashlib.sha1(pt).hexdigest())
open('extracted/artifacts/task8_decrypted.bin','wb').write(pt)
PY
resource: xxxxxxxxxxxxxxxxxxxxxxxxxxxx.exe
b'MZ' 49664 052c0687f023564a3c31fb652bea3405341272cb
```

Decrypted implant strings as `MasonClient1` / `MasonRAT` / `NeptuneRAT V5.3`. Three User-Agents ; mobile one is the iPhone Safari string. Mutex field is obfuscated VB.NET name `Territories` (`System.Threading.Mutex`). C2 host `apostlejob3.duckdns.org` port `2468` :

```bash
> dig +short apostlejob3.duckdns.org A
107.172.232.84
```

Persistence is already on the image under the user Startup folder — same bat body as `dwm.bat` :

```bash
> ls -la "extracted/artifacts/5c74.bat"
> # AD1 path :
> # C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\5c74.bat
```

Chain in one line : zip lure → `Conf.js` (WSCRIPT) → `temp_993805.bat` → `dwm.bat` + AMSI patch → in-memory .NET loaders → decrypt `xxxxxxxxxxxxxxxxxxxxxxxxxxxx.exe` → Neptune/Mason RAT → intended C2 `107.172.232.84:2468`, Startup `5c74.bat`. Containment cut the channel before full C2 ; IoCs still sit in the staged files.

