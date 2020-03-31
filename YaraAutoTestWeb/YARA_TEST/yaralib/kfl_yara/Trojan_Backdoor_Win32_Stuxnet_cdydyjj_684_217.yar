rule Trojan_Backdoor_Win32_Stuxnet_cdydyjj_684_217
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Stuxnet.cdydyjj"
        threattype = "Backdoor"
        family = "Stuxnet"
        hacker = "None"
        author = "balala"
        refer = "4589ef6876e9c8c05dcf4db00a54887b,37fc7c5d89f1e5a96f54318df1a2b905"
        comment = "None"
        date = "2018-09-05"
        description = "None"
	strings:
        $x1 = "SHELL32.DLL.ASLR." fullword wide
        $s1 = "~WTR4141.tmp" fullword wide
        $s2 = "~WTR4132.tmp" fullword wide
        $s3 = "totalcmd.exe" fullword wide
        $s4 = "wincmd.exe" fullword wide
        $s5 = "http://www.realtek.com0" fullword ascii
        $s6 = "{%08x-%08x-%08x-%08x}" fullword wide

    condition:
        ( uint16(0) == 0x5a4d and filesize < 150KB and ( $x1 or 3 of ($s*) ) ) or ( 5 of them )

}