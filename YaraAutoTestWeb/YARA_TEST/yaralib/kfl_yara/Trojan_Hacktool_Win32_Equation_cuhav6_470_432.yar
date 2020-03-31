rule Trojan_Hacktool_Win32_Equation_cuhav6_470_432
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.cuhav6"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "d42d0cac604ea47b26f8cb0e0a9d028e"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-24"
        description = "Equation Group hack tool set EquationGroup_cursehappy_win2k_v_6_1_0 "
	strings:
		$op1 = { e8 24 2c 01 00 85 c0 89 c6 ba ff ff ff ff 74 d6 } /* Opcode */
		$op2 = { 89 4c 24 04 89 34 24 89 44 24 08 e8 ce 49 ff ff } /* Opcode */
	condition:
		( uint16(0) == 0x5a4d and filesize < 400KB and all of them )
}