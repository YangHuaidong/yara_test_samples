rule Trojan_Hacktool_Linux_Equation_wterv3_466_412
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Linux.Equation.wterv3"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "4cff303878f74178ad9d892c9a69e405"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-30"
        description = "Equation Group hack tool set EquationGroup_watcher_linux_i386_v_3_3_0"
	strings:
		$s1 = "invalid option `" fullword ascii
		$s8 = "readdir64" fullword ascii
		$s9 = "89:z89:%r%opw" fullword wide
		$s13 = "Ropopoprstuvwypypop" fullword wide
		$s17 = "Missing argument for `-x'." fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 700KB and all of them )
}