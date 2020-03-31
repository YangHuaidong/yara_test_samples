rule Trojan_Backdoor_Linux_Equation_sshobo_372_18
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Linux.Equation.sshobo"
        threattype = "Backdoor"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "07e7f2cf4adcd4d17bd337739ed05df1"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-02"
        description = "Equation Group hack tool leaked by ShadowBrokers- sshobo"
	strings:
		$x1 = "Requested forwarding of port %d but user is not root." fullword ascii
		$x2 = "internal error: we do not read, but chan_read_failed for istate" fullword ascii
		$x3 = "~#  - list forwarded connections" fullword ascii
		$x4 = "packet_inject_ignore: block" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 600KB and all of them )
}