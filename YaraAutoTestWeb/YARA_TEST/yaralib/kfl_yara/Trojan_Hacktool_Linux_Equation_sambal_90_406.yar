rule Trojan_Hacktool_Linux_Equation_sambal_90_406
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Linux.Equation.sambal"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "ef6e23f6422e67c42d50d7bc8a78e796"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-09"
        description = "Equation Group hack tool leaked by ShadowBrokers- file sambal"
	strings:
		$s1 = "+ Bruteforce mode." fullword ascii
		$s3 = "+ Host is not running samba!" fullword ascii
		$s4 = "+ connecting back to: [%d.%d.%d.%d:45295]" fullword ascii
		$s5 = "+ Exploit failed, try -b to bruteforce." fullword ascii
		$s7 = "Usage: %s [-bBcCdfprsStv] [host]" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 90KB and 1 of them ) or ( 2 of them )
}