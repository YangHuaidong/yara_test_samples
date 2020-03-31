rule Trojan_Hacktool_Win32_Equation_cufswiv1_457_431
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.cufswiv1"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "46a724598d9f999c84c6d8b3f9e2b8a8"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-24"
        description = "Equation Group hack tool set curseflower_mswin32_v_1_0_0 "
	strings:
		$s1 = "<pVt,<et(<st$<ct$<nt" fullword ascii
		$op1 = { 6a 04 83 c0 08 6a 01 50 e8 10 34 00 00 83 c4 10 } /* Opcode */
	condition:
		( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}