rule Trojan_Hacktool_Linux_Equation_cuzlv2_447_383
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Linux.Equation.cuzlv2"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "d329989a712a7593da543090ae5d08a2"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-24"
        description = "Equation Group hack tool set cursezinger_linuxrh7_3_v_2_0_0"
	strings:
		$s1 = ",%02d%03d" fullword ascii
		$s2 = "[%.2u%.2u%.2u%.2u%.2u%.2u]" fullword ascii
		$s3 = "__strtoll_internal" fullword ascii
		$s4 = "__strtoul_internal" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 400KB and all of them )
}