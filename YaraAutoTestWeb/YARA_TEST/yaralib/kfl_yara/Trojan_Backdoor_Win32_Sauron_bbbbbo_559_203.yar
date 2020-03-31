rule Trojan_Backdoor_Win32_Sauron_bbbbbo_559_203
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Sauron.bbbbbo"
        threattype = "Backdoor"
        family = "Sauron"
        hacker = "None"
        author = "balala"
        refer = "2a8785bf45f4f03c10cd929bb0685c2d,b98227f8116133dc8060f2ada986631c"
		comment = "None"
        date = "2018-08-09"
        description = "None"
    

    strings:
        $sx1 = "Default user" fullword wide
        $sx2 = "Hincorrect header check" fullword ascii /* Typo */
        $sa1 = "MSAOSSPC.dll" fullword ascii
        $sa2 = "MSAOSSPC.DLL" fullword wide
        $sa3 = "MSAOSSPC" fullword wide
        $sa4 = "AOL Security Package" fullword wide
        $sa5 = "AOL Security Package" fullword wide
        $sa6 = "AOL Client for 32 bit platforms" fullword wide
        $op0 = { 8b ce 5b e9 4b ff ff ff 55 8b ec 51 53 8b 5d 08 } /* Opcode */
        $op1 = { e8 0a fe ff ff 8b 4d 14 89 46 04 89 41 04 8b 45 } /* Opcode */
        $op2 = { e9 29 ff ff ff 83 7d fc 00 0f 84 cf 0a 00 00 8b } /* Opcode */
        $op3 = { 83 f8 0c 0f 85 3a 01 00 00 44 2b 41 6c 41 8b c9 } /* Opcode */
        $op4 = { 44 39 57 0c 0f 84 d6 0c 00 00 44 89 6f 18 45 89 } /* Opcode */
        $op5 = { c1 ed 02 83 c6 fe e9 68 fe ff ff 44 39 57 08 75 } /* Opcode */
   
    condition:
        uint16(0) == 0x5a4d and filesize < 200KB and (( 3 of ($s*) and 3 of ($op*) ) or ( 1 of ($sx*) and 1 of ($sa*) ))
}