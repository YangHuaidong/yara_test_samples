rule Trojan_Hacktool_Linux_Equation_orssv2_452_399
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Linux.Equation.orssv2"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "dc8da4049f78ed7df868f2e22cf6ce3f"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-24"
        description = "Equation Group hack tool set orleans_stride_sunos5_9_v_2_4_0"
	strings:
		$s1 = "_lib_version" fullword ascii
		$s2 = ",%02d%03d" fullword ascii
		$s3 = "TRANSIT" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 200KB and all of them )
}