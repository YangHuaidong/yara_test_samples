rule Trojan_Hacktool_Win32_Equation_cuw2kv2_459_434
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.cuw2kv2"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "18c701485a21fc0789011c45858ff933"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-24"
        description = "Equation Group hack tool set curseroot_win2k_v_2_1_0 "
	strings:
		$s1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/%s,%s" fullword ascii
		$op0 = { c7 44 24 04 ff ff ff ff 89 04 24 e8 46 65 01 00 } /* Opcode */
		$op1 = { 8d 5d 88 89 1c 24 e8 24 1b 01 00 be ff ff ff ff } /* Opcode */
		$op2 = { d3 e0 48 e9 0c ff ff ff 8b 45 } /* Opcode */
	condition:
		( uint16(0) == 0x5a4d and filesize < 400KB and $s1 and 2 of ($op*) )
}