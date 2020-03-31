rule Trojan_Hacktool_Linux_Equation_wasov3_456_411
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Linux.Equation.wasov3"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "f315e5d94d816a037a33a6595898ece8"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-24"
        description = "Equation Group hack tool set watcher_solaris_i386_v_3_3_0"
	strings:
		$s1 = "getexecname" fullword ascii
		$s2 = "invalid option `" fullword ascii
		$s6 = "__fpstart" fullword ascii
		$s12 = "GHFIJKLMNOPQRSTUVXW" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 700KB and all of them )
}