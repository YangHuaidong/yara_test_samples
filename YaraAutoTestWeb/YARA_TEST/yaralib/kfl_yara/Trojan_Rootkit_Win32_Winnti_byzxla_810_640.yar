rule Trojan_Rootkit_Win32_Winnti_byzxla_810_640
{
    meta:
        judge = "black"
        threatname = "Trojan[Rootkit]/Win32.Winnti.byzxla"
        threattype = "Rootkit"
        family = "Winnti"
        hacker = "None"
        author = "balala"
        refer = "326cbe7a0eed991ef7fc3d59d7728c6f,b5012e2d3ff209c6da346ccad709d23f,68fd2aa16f3b4597cbd446676fade3eb,ecc7f180d438663185466a9783bd0790,0479ef126c9b96585b5b09de72c46919"
        comment = "None"
        date = "2018-10-22"
        description = "None"
	strings:
        $x1 = "\\Driver\\nsiproxy" fullword wide
        $a1 = "\\Device\\StreamPortal" fullword wide
        $a2 = "\\Device\\PNTFILTER" fullword wide
        $s1 = "Cookie: SN=" fullword ascii
        $s2 = "\\BaseNamedObjects\\_transmition_synchronization_" fullword wide
        $s3 = "Winqual.sys" fullword wide
        $s4 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}" fullword wide
        $s5 = "http://www.wasabii.com.tw 0" fullword ascii
    
    condition:
        uint16(0) == 0x5a4d and $x1 and 1 of ($a*) and 2 of ($s*)
}