rule Trojan_Hacktool_Linux_Equation_moratc_464_397
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Linux.Equation.moratc"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "fa9753c25c8be1134ace6d77dae3f5a4"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-30"
        description = "Equation Group hack tool set EquationGroup_morerats_client_Store"
	strings:
		$s1 = "[-] Failed to mmap file: %s" fullword ascii
		$s2 = "[-] can not NULL terminate input data" fullword ascii
		$s3 = "Missing argument for `-x'." fullword ascii
		$s4 = "[!] Value has size of 0!" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 60KB and 2 of them )
}