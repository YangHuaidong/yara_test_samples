rule Trojan_Hacktool_Linux_Equation_exze_82_390
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Linux.Equation.exze"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "cb00ebbe477d7c23489122e7fcc5f229"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-09"
        description = "Equation Group hack tool leaked by ShadowBrokers- file exze"
	strings:
		$s1 = "shellFile" fullword ascii
		$s2 = "completed.1" fullword ascii
		$s3 = "zeke_remove" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 80KB and all of them )
}