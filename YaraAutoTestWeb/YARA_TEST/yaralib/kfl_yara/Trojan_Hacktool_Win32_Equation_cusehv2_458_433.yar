rule Trojan_Hacktool_Win32_Equation_cusehv2_458_433
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.cusehv2"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "e0b0015e0be0a0d42495e63971016716"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-24"
        description = "Equation Group hack tool set EquationGroup_cursehelper_win2k_i686_v_2_2_0 "
	strings:
		$s1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/{}" fullword ascii
		$op1 = { 8d b5 48 ff ff ff 89 34 24 e8 56 2a 00 00 c7 44 } /* Opcode */
		$op2 = { e9 a2 f2 ff ff ff 85 b4 fe ff ff 8b 95 a8 fe ff } /* Opcode */
	condition:
		( uint16(0) == 0x5a4d and filesize < 500KB and all of them )
}