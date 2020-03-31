rule Trojan_Hacktool_Win32_Equation_lpmstcp_605_486
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.lpmstcp"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "075983e8b43cc98e6ab4a0dbed0324fe"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-20"
        description = "Equation Group hack tool set lp_mstcp "
	strings:
		$s1 = "\\Registry\\User\\CurrentUser\\" fullword wide
		$s2 = "_PacketNDISRequestComplete@12\"" fullword ascii
		$s3 = "_LDNdis5RegDeleteKeys@4" fullword ascii
		$op1 = { 89 7e 04 75 06 66 21 46 02 eb }
		$op2 = { fc 74 1b 8b 49 04 0f b7 d3 66 83 }
		$op3 = { aa 0f b7 45 fc 8b 52 04 8d 4e }
	condition:
		( uint16(0) == 0x5a4d and filesize < 100KB and ( all of ($s*) or all of ($op*) ) )
}