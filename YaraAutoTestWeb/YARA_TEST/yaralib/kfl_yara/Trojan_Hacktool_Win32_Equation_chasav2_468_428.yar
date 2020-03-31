rule Trojan_Hacktool_Win32_Equation_chasav2_468_428
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.chasav2"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "d18ef43590a4bcb64fcc30622244159c"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-24"
        description = "Equation Group hack tool set EquationGroup_charm_saver_win2k_v_2_0_0 "
	strings:
		$s2 = "0123456789abcdefABCEDF:" fullword ascii
		$op0 = { b8 ff ff ff ff 7f 65 eb 30 8b 55 0c 89 d7 0f b6 } /* Opcode */
		$op2 = { ba ff ff ff ff 83 c4 6c 89 d0 5b 5e 5f 5d c3 90 } /* Opcode */
	condition:
		( uint16(0) == 0x5a4d and filesize < 400KB and all of them )
}