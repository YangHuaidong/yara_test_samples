rule Trojan_Backdoor_Win32_Sauron_bbbbbgj_556_200
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Sauron.bbbbbj"
        threattype = "Backdoor"
        family = "Sauron"
        hacker = "None"
        author = "balala"
        refer = "6cd8311d11dc973e970237e10ed04ad7"
		comment = "None"
        date = "2018-08-09"
        description = "None"
    

    strings:
        $s1 = "ExampleProject.dll" fullword ascii
        $op0 = { 8b 4f 06 85 c9 74 14 83 f9 13 0f 82 ba } /* Opcode */
        $op1 = { ff 15 34 20 00 10 85 c0 59 a3 60 30 00 10 75 04 } /* Opcode */
        $op2 = { 55 8b ec ff 4d 0c 75 09 ff 75 08 ff 15 00 20 00 } /* Opcode */
 
    condition:
        ( uint16(0) == 0x5a4d and filesize < 1000KB and ( all of ($s*) ) and all of ($op*) )
}