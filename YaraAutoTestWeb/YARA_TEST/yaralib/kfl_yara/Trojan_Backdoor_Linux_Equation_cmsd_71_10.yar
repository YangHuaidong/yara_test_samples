rule Trojan_Backdoor_Linux_Equation_cmsd_71_10
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Linux.Equation.cmsd"
        threattype = "Backdoor"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "0aae154de9d7d48f76a0949322c3966b"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-09"
        description = "Equation Group hack tool leaked by ShadowBrokers- file cmsd"
	strings:
		$x1 = "usage: %s address [-t][-s|-c command] [-p port] [-v 5|6|7]" fullword ascii
		$x2 = "error: not vulnerable" fullword ascii
		$s1 = "port=%d connected! " fullword ascii
		$s2 = "xxx.XXXXXX" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 30KB and 1 of ($x*) ) or ( 2 of them )
}