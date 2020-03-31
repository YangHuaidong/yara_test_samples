rule Trojan_Hacktool_Linux_Equation_storev3_455_409
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Linux.Equation.storev3"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "b0c896822c41bc1d6a6abb82ce3a4105"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-24"
        description = "Equation Group hack tool set"
	strings:
		$s1 = "[-] Failed to map file: %s" fullword ascii
		$s2 = "[-] can not NULL terminate input data" fullword ascii
		$s3 = "[!] Name has size of 0!" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 60KB and all of them )
}