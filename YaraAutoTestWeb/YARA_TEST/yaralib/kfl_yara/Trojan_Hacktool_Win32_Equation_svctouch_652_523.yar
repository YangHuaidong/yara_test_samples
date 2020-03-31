rule Trojan_Hacktool_Win32_Equation_svctouch_652_523
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.svctouch"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "ce0095c5824e6420f3a2bd1e8afc9453"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-27"
        description = "Equation Group hack tool set svctouch "
	strings:
		$s1 = "Causes: Firewall,Machine down,DCOM disabled\\not supported,etc." fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 10KB and 1 of them )
}	