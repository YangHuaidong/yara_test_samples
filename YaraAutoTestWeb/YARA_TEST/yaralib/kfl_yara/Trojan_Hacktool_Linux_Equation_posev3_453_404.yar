rule Trojan_Hacktool_Linux_Equation_posev3_453_404
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Linux.Equation.posev3"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "07b8fc7df501ee020c33bcd230498e1d"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-24"
        description = "Equation Group hack tool set porkserver_v3_0_0 "
	strings:
		$s1 = "%s: %s rpcprog=%d, rpcvers = %d/%d, proto=%s, wait.max=%d.%d, user.group=%s.%s builtin=%lx server=%s" fullword ascii
		$s2 = "%s/%s server failing (looping), service terminated" fullword ascii
		$s3 = "getpwnam: %s: No such user" fullword ascii
		$s4 = "execv %s: %m" fullword ascii
		$s5 = "%s/%s: getsockname: %m" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 70KB and 4 of them )
}