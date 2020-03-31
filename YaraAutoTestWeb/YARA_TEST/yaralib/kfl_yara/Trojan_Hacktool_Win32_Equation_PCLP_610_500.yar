rule Trojan_Hacktool_Win32_Equation_PCLP_610_500
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.PCLP"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "4388dd9f4cd98db1eab4e08f72ad7d6a"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-20"
        description = "Equation Group hack tool set PC_LP "
	strings:
		$s1 = "* Failed to get connection information.  Aborting launcher!" fullword wide
		$s2 = "Format: <command> <target port> [lp port]" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}