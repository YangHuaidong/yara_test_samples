rule Trojan_Hacktool_Win32_Equation_SeOuAd_650_517
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.SeOuAd"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "6e0bb46144359d37eaceb5f60d168f6e"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-20"
        description = "Equation Group hack tool set SetOurAddr "
	strings:
		$s1 = "USAGE: SetOurAddr <input file> <output file> <protocol> [IP/IPX address]" fullword ascii
		$s2 = "Replaced default IP address (127.0.0.1) with Local IP Address %d.%d.%d.%d" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}