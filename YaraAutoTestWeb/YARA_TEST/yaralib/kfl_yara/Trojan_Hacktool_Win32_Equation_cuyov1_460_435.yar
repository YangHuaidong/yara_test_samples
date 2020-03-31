rule Trojan_Hacktool_Win32_Equation_cuyov1_460_435
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.cuyov1"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "e3a0a95f604be9081b6ecc105ed3e021"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-24"
        description = "Equation Group hack tool set curseyo_win2k_v_1_0_0 "
	strings:
		$s1 = "0123456789abcdefABCEDF:" fullword ascii
		$op0 = { c6 06 5b 8b bd 70 ff ff ff 8b 9d 64 ff ff ff 0f } /* Opcode */
		$op1 = { 55 b8 ff ff ff ff 89 e5 83 ec 28 89 7d fc 8b 7d } /* Opcode */
		$op2 = { ff 05 10 64 41 00 89 34 24 e8 df 1e 00 00 e9 31 } /* Opcode */
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}