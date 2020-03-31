rule Trojan_Backdoor_Win32_Symmi_hhxxhql_750_224
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Symmi.hhxxhql"
        threattype = "Backdoor"
        family = "Symmi"
        hacker = "None"
        author = "ljy"
        refer = "d0eec2294a70ceff84ca8d0ed7939fb5,81ed752590752016cb1c12f3e9ab3454"
        comment = "None"
        date = "2018-09-20"
        description = "None"
	strings:
        $s0 = "update.hancominc.com" fullword wide 
   
    condition:
        uint16(0) == 0x5a4d and filesize < 100KB and $s0
}