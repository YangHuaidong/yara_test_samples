rule Trojan_Hacktool_Linux_Equation_cumsv1_445_381
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Linux.Equation.cumsv1"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "725de0eb16106f3cf6c28eaeac43d541"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-24"
        description = "Equation Group hack tool set cursesleepy_mswin32_v_1_0_0"
	strings:
		$s1 = "A}%j,R" fullword ascii
		$op1 = { a1 e0 43 41 00 8b 0d 34 44 41 00 6b c0 } /* Opcode */
		$op2 = { 33 C0 F3 A6 74 14 8B 5D 08 8B 4B 34 50 } /* Opcode */
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and 2 of them )
}