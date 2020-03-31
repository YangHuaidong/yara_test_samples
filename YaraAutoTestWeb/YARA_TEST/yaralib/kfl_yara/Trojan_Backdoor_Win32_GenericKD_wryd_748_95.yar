rule Trojan_Backdoor_Win32_GenericKD_wryd_748_95
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.GenericKD.wryd"
        threattype = "Backdoor"
        family = "GenericKD"
        hacker = "None"
        author = "ljy"
        refer = "728e5700a401498d91fb83159beec834,bbfd1e703f55ce779b536b5646a0cdc1"
        comment = "None"
        date = "2018-09-20"
        description = "None"
	strings:
        $s1 = "navlu.dll.urlUT" fullword ascii
        $s2 = "VPDN_LU.exeUT" fullword ascii
        $s3 = "pnipcn.dllUT" fullword ascii
        $s4 = "\\ssonsvr.exe" fullword ascii
        $s5 = "/c del /q %s" fullword ascii
        $s6 = "\\setup.exe" fullword ascii 
        $s7 = "msi.dllUT" fullword ascii
        $op0 = { 8b 45 0c 83 38 00 0f 84 98 } /* Opcode */
        $op1 = { e8 dd 07 00 00 ff 35 d8 fb 40 00 8b 35 7c a0 40 } /* Opcode */
        $op2 = { 83 fb 08 75 2c 8b 0d f8 af 40 00 89 4d dc 8b 0d } /* Opcode */
        $op3 = { c7 43 18 8c 69 40 00 e9 da 01 00 00 83 7d f0 00 } /* Opcode */
        $op4 = { 6a 01 e9 7c f8 ff ff bf 1a 40 00 96 1b 40 00 01 } /* Opcode */

    condition:
        uint16(0) == 0x5a4d and filesize < 400KB and 3 of ($s*) and 1 of ($op*)
}