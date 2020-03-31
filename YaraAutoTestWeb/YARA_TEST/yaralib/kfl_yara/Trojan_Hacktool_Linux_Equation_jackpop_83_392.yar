rule Trojan_Hacktool_Linux_Equation_jackpop_83_392
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Linux.Equation.jackpop"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "e67cb0e8513f5a149b3d98d305db2ea3"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-09"
        description = "Equation Group hack tool leaked by ShadowBrokers- file jackpop"
	strings:
		$x1 = "%x:%d  --> %x:%d %d bytes" fullword ascii
		$s1 = "client: can't bind to local address, are you root?" fullword ascii
		$s2 = "Unable to register port" fullword ascii
		$s3 = "Could not resolve destination" fullword ascii
		$s4 = "raw troubles" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 30KB and 3 of them ) or ( all of them )
}