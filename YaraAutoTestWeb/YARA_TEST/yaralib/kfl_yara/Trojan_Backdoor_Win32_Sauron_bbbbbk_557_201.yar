rule Trojan_Backdoor_Win32_Sauron_bbbbbgk_557_201
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Sauron.bbbbbk"
        threattype = "Backdoor"
        family = "Sauron"
        hacker = "None"
        author = "balala"
        refer = "137211edefb9e7f8aa64f6e800b749b4"
		comment = "None"
        date = "2018-08-09"
        description = "None"
    

    strings:
        $s1 = "xpsmngr.dll" fullword wide
        $s2 = "XPS Manager" fullword wide
        $op0 = { 89 4d e8 89 4d ec 89 4d f0 ff d2 3d 08 00 00 c6 } /* Opcode */
        $op1 = { 55 8b ec ff 4d 0c 75 09 ff 75 08 ff 15 04 20 5b } /* Opcode */
        $op2 = { 8b 4f 06 85 c9 74 14 83 f9 13 0f 82 b6 } /* Opcode */

    condition:
        ( uint16(0) == 0x5a4d and filesize < 90KB and ( all of ($s*) ) and 1 of ($op*) ) or ( all of them )
}