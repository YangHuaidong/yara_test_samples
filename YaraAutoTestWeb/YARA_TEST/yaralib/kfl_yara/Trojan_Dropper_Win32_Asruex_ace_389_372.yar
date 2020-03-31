rule Trojan_Dropper_Win32_Asruex_ace_389_372
{
    meta:
        judge = "black"
        threatname = "Trojan[Dropper]/Win32.Asruex.ace"
        threattype = "Dropper"
        family = "Asruex"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "891b5bbc60fab52620e446dcc0d85bda"
        comment = "None"
        date = "2018-06-20"
        description = "Detects sample mentioned in the Dubnium Report"
    strings:
        $x1 = "copy /y \"%s\" \"%s\" " fullword ascii
        $x2 = "del /f \"%s\" " fullword ascii
        $s1 = "del /f /ah \"%s\" " fullword ascii
        $s2 = "if exist \"%s\" goto Rept " fullword ascii
        $s3 = "\\*.*.lnk" fullword ascii
        $s4 = "Dropped" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 2000KB and 5 of them
}