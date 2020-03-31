rule Trojan_Backdoor_Win32_Sauron_bbbbbgh_555_199
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Sauron.bbbbbh"
        threattype = "Backdoor"
        family = "Sauron"
        hacker = "None"
        author = "balala"
        refer = "234e22d3b7bba6c0891de0a19b79d7ea"
		comment = "None"
        date = "2018-08-09"
        description = "None"
    

    strings:
        $s2 = "\\*\\3vpn" fullword ascii
        $op0 = { 55 8b ec 83 ec 0c 53 56 33 f6 39 75 08 57 89 75 } /* Opcode */
        $op1 = { 59 59 c3 8b 65 e8 ff 75 88 ff 15 50 20 40 00 ff } /* Opcode */
        $op2 = { 8b 4f 06 85 c9 74 14 83 f9 12 0f 82 a7 } /* Opcode */
    
    condition:
        ( uint16(0) == 0x5a4d and filesize < 400KB and ( all of ($s*) ) and all of ($op*) )
}