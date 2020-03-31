rule Trojan_Hacktool_Linux_Equation_cursm_446_382
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Linux.Equation.cursm"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "75832ee35ce1c2d18cab5fd2992e33ea"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-24"
        description = "Equation Group hack tool set cursetingle_2_0_1_2_mswin32_v_2_0_1"
	strings:
		$s1 = "[%.2u%.2u%.2u%.2u%.2u%.2u]" fullword ascii
		$s2 = "0123456789abcdefABCEDF:" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}