rule Trojan_Hacktool_Win32_Equation_CFPKv6_691_427
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.CFPKv6"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "231303ccfc993b1fc9cd701dad58e449,83ed8b6065add87a32104101eb30bd31"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-09-03"
        description = "Equation Group hack tool set SendCFTrigger_SendPKTrigger_6 "
	strings:
		$s4 = "* Failed to connect to destination - %u" fullword wide
		$s6 = "* Failed to convert destination address into sockaddr_storage values" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 400KB and 1 of them )
}