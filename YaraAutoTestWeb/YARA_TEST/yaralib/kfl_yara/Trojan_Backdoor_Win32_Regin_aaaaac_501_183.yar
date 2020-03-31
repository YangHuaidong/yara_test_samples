rule Trojan_Backdoor_Win32_Regin_aaaaac_501_183
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Regin.aaaaac"
        threattype = "Backdoor"
        family = "Regin"
        hacker = "None"
        author = "balala"
        refer = "187044596bc1328efa0ed636d8aa4a5c,06665b96e293b23acc80451abb413e50,d240f06e98c8d3e647cbf4d442d79475"
		comment = "None"
        date = "2018-08-02"
        description = "Generic rule for Regin APT kernel driver Malware - Symantec http://t.co/qu53359Cb2"
    

    strings:
        $m0 = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 } 
        $m1 = { 0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e }    
        $s0 = "atapi.sys" fullword wide
        $s1 = "disk.sys" fullword wide
        $s3 = "h.data" fullword ascii
        $s4 = "\\system32" fullword ascii
        $s5 = "\\SystemRoot" fullword ascii
        $s6 = "system" fullword ascii
        $s7 = "temp" fullword ascii
        $s8 = "windows" fullword ascii
        $x1 = "LRich6" fullword ascii
        $x2 = "KeServiceDescriptorTable" fullword ascii     
    
    condition:
        $m0 at 0 and $m1 and all of ($s*) and 1 of ($x*)
}