rule Trojan_Hacktool_Linux_Equation_porkse_88_403
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Linux.Equation.porkse"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "07b8fc7df501ee020c33bcd230498e1d"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-09"
        description = "Equation Group hack tool leaked by ShadowBrokers- file porkserver"
	strings:
		$s1 = "%s/%s server failing (looping), service terminated" fullword ascii
		$s2 = "getpwnam: %s: No such user" fullword ascii
		$s3 = "execv %s: %m" fullword ascii
		$s4 = "%s/%s: unknown service" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 70KB and 3 of them )
}