rule Trojan_Hacktool_Linux_Equation_cmsex_78_380
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Linux.Equation.cmsex"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "f1e54a229382cf42833dbb0da1a92456"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-09"
        description = "Equation Group hack tool leaked by ShadowBrokers- file cmsex"
	strings:
		$x1 = "Usage: %s -i <ip_addr/hostname> -c <command> -T <target_type> (-u <port> | -t <port>) " fullword ascii
		$x2 = "-i target ip address / hostname " fullword ascii
		$x3 = "Note: Choosing the correct target type is a bit of guesswork." fullword ascii
		$x4 = "Solaris rpc.cmsd remote root exploit" fullword ascii
		$x5 = "If one choice fails, you may want to try another." fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 50KB and 1 of ($x*) ) or ( 2 of them )
}