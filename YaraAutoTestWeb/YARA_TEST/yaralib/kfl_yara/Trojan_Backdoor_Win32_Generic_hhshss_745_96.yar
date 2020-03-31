rule Trojan_Backdoor_Win32_Generic_hhshss_745_96
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Generic.hhshss"
        threattype = "Backdoor"
        family = "Generic"
        hacker = "None"
        author = "ljy"
        refer = "1cb4b74e9d030afbb18accf6ee2bfca1,2bec1860499aae1dbcc92f48b276f998,93e40da0bd78bebe5e1b98c6324e9b5b,4251aaf38a485b08d5562c6066370f09,b333b5d541a0488f4e710ae97c46d9c2,f43d9c3e17e8480a36a62ef869212419,12a522cb96700c82dc964197adb57ddf"
        comment = "None"
        date = "2018-09-20"
        description = "None"
	strings:
        $x1 = "1001=cmd.exe" fullword ascii 
        $x2 = "1003=ShellExecuteA" fullword ascii 
        $x3 = "1002=/c del /q %s" fullword ascii
        $x4 = "1004=SetThreadPriority" fullword ascii

        /* $s1 = "pnipcn.dllUT" fullword ascii
        $s2 = "ssonsvr.exeUT" fullword ascii
        $s3 = "navlu.dllUT" fullword ascii
        $s4 = "@CONOUT$" fullword wide 
        $s5 = "VPDN_LU.exeUT" fullword ascii
        $s6 = "msi.dll.urlUT" fullword ascii
        $s7 = "setup.exeUT" fullword ascii 
        $s8 = "pnipcn.dll.urlUT" fullword ascii
        $s9 = "ldvpreg.exeUT" fullword ascii */

        $op0 = { e8 71 11 00 00 83 c4 10 ff 4d e4 8b f0 78 07 8b } /* Opcode */
        $op1 = { e8 85 34 00 00 59 59 8b 86 b4 } /* Opcode */
        $op2 = { 8b 45 0c 83 38 00 0f 84 97 } /* Opcode */
        $op3 = { 8b 45 0c 83 38 00 0f 84 98 } /* Opcode */
        $op4 = { 89 7e 0c ff 15 a0 50 40 00 59 8b d8 6a 20 59 8d } /* Opcode */
        $op5 = { 56 8d 85 cd fc ff ff 53 50 88 9d cc fc ff ff e8 } /* Opcode */
    
    condition:
        uint16(0) == 0x5a4d and filesize < 400KB and all of ($x*) and 1 of ($op*)
}