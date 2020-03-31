rule Trojan_Hacktool_Linux_Equation_seImp3_454_407
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Linux.Equation.seImp3"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "c8d2fbac602fa261aa58276a2fd1c1d9"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-24"
        description = "Equation Group hack tool set seconddate_ImplantStandalone_3_0_3"
	strings:
		$s1 = "EFDGHIJKLMNOPQRSUT" fullword ascii
		$s2 = "G8HcJ HcF LcF0LcN" fullword ascii
		$s3 = "GhHcJ0HcF@LcF0LcN8H" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 1000KB and all of them )
}