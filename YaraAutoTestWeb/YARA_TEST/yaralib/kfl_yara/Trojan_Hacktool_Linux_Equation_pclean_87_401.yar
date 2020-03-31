rule Trojan_Hacktool_Linux_Equation_pclean_87_401
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Linux.Equation.pclean"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "e2a0a09fef76786b8a87bfc103898ef8"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-09"
        description = "Equation Group hack tool leaked by ShadowBrokers- file pclean.v2.1.1.0-linux-i386"
	strings:
		$s3 = "** SIGNIFICANTLY IMPROVE PROCESSING TIME" fullword ascii
		$s6 = "-c cmd_name:     strncmp() search for 1st %d chars of commands that " fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 40KB and all of them )
}