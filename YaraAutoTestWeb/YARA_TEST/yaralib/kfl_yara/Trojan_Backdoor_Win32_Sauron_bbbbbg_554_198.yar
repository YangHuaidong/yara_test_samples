rule Trojan_Backdoor_Win32_Sauron_bbbbbg_554_198
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Sauron.bbbbbg"
        threattype = "Backdoor"
        family = "Sauron"
        hacker = "None"
        author = "balala"
        refer = "1f316e14e773ca0f468d0d160b5d0307"
		comment = "None"
        date = "2018-08-09"
        description = "None"
    

    strings:
        $s1 = "ncnfloc.dll" fullword wide
        $s4 = "Network Configuration Locator" fullword wide

        $op0 = { 80 75 6e 85 c0 79 6a 66 41 83 38 0a 75 63 0f b7 } /* Opcode */
        $op1 = { 80 75 29 85 c9 79 25 b9 01 } /* Opcode */
        $op2 = { 2b d8 48 89 7c 24 38 44 89 6c 24 40 83 c3 08 89 } /* Opcode */

    condition:
        ( uint16(0) == 0x5a4d and filesize < 200KB and ( all of ($s*) ) and 1 of ($op*) ) or ( all of them )
}