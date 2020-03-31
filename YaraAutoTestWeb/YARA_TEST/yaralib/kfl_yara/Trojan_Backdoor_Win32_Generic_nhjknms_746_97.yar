rule Trojan_Backdoor_Win32_Generic_nhjknms_746_97
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Generic.nhjknms"
        threattype = "Backdoor"
        family = "Generic"
        hacker = "None"
        author = "ljy"
        refer = "728e5700a401498d91fb83159beec834"
        comment = "None"
        date = "2018-09-20"
        description = "None"
	strings:
        $s0 = "nKERNEL32.DLL" fullword wide
        $s1 = "WUSER32.DLL" fullword wide
        $s2 = "mscoree.dll" fullword wide
        $s3 = "VPDN_LU.exeUT" fullword ascii
   
    condition:
        uint16(0) == 0x5a4d and filesize < 250KB and all of them
}