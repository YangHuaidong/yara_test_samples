rule Trojan_Backdoor_Win32_Sauron_bbbbbl_558_202
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Sauron.bbbbbl"
        threattype = "Backdoor"
        family = "Sauron"
        hacker = "None"
        author = "balala"
        refer = "7b8a3bf6fd266593db96eddaa3fae6f9"
		comment = "None"
        date = "2018-08-09"
        description = "None"
    

    strings:
        $s1 = "rseceng.dll" fullword wide
        $s2 = "Remote Security Engine" fullword wide
        $op0 = { 8b 0d d5 1d 00 00 85 c9 0f 8e a2 } /* Opcode */
        $op1 = { 80 75 6e 85 c0 79 6a 66 41 83 38 0a 75 63 0f b7 } /* Opcode */
        $op2 = { 80 75 29 85 c9 79 25 b9 01 } /* Opcode */
   
    condition:
        ( uint16(0) == 0x5a4d and filesize < 200KB and ( all of ($s*) ) and 1 of ($op*) ) or ( all of them )
}