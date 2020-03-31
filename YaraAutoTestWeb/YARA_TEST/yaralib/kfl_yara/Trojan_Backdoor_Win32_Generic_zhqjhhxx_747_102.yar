rule Trojan_Backdoor_Win32_Generic_zhqjhhxx_747_102
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Generic.zhqjhhxx"
        threattype = "Backdoor"
        family = "Generic"
        hacker = "None"
        author = "ljy"
        refer = "8dacca7dd24844935fcd34e6c9609416,462fd01302bc40624a44b7960d2894cd,f7a842eb1364d1269b40a344510068e8,b313bbe17bd5ee9c00acff3bfccdb48a,7cffd679599fb8579abae8f32ce49026"
        comment = "None"
        date = "2018-09-20"
        description = "None"
	strings:
        $s0 = "NvSmartMax.dll" fullword ascii
        $s1 = "NvSmartMax.dll.url" fullword ascii
        $s2 = "Nv.exe" fullword ascii
        $s4 = "CryptProtectMemory failed" fullword ascii 
        $s5 = "CryptUnprotectMemory failed" fullword ascii 
        $s7 = "r%.*s(%d)%s" fullword wide
        $s8 = " %s CRC " fullword wide
        $op0 = { c6 05 26 49 42 00 01 eb 4a 8d 85 00 f8 ff ff 50 } /* Opcode */
        $op1 = { 8d 85 c8 fe ff ff 50 8d 45 c8 50 c6 45 47 00 e8 } /* Opcode */
        $op2 = { e8 e6 65 00 00 50 68 10 43 41 00 e8 56 84 00 00 } /* Opcode */
 
    condition:
        uint16(0) == 0x5a4d and filesize < 800KB and all of ($s*) and 1 of ($op*)
}