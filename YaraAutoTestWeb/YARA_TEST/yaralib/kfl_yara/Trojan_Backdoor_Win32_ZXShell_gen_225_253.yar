import "pe"
rule Trojan_Backdoor_Win32_ZXShell_gen_225_253
{

    meta:
        judge = "black"
        threatname = "Trojan[backdoor]/Win32.ZXShell.gen"
        threattype = "backdoor"
        family = "ZXShell"
        hacker = "None"
        author = "Florian Roth-mqx"
        refer = "f2449ecf637a370b6a0632a4b45cd554,8d20017f576fbd58cce25637d29826ca,d3bf38bcf3a88e22eb6f5aad42f52846,e61a40e9ddccc2412435d2f22b4227c2"
        comment = "None"
        date = "2018-07-19"
        description = "PassCV Malware mentioned in Cylance Report"

   strings:
        $x1 = "ncProxyXll" fullword ascii
        $s1 = "Uniscribe.dll" fullword ascii
        $s2 = "WS2_32.dll" ascii
        $s3 = "ProxyDll" fullword ascii
        $s4 = "JDNSAPI.dll" fullword ascii
        $s5 = "x64.dat" fullword ascii
        $s6 = "LSpyb2" fullword ascii

   condition:
        (uint16(0) == 0x5a4d and filesize < 4000KB and $x1 ) or ( all of them )
}