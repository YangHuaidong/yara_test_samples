rule Trojan_Hacktool_Win32_Equation_PacScImp_608_495
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.PacScImp"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "138d1bd5ddf6a45d57773a7b9a379499"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-20"
        description = "Equation Group hack tool set PacketScan_Implant "
	strings:
		$op0 = { e9 ef fe ff ff ff b5 c0 ef ff ff 8d 85 c8 ef ff }
		$op1 = { c9 c2 04 00 b8 34 26 00 68 e8 40 05 00 00 51 56 }
		$op2 = { e9 0b ff ff ff 8b 45 10 8d 4d c0 89 58 08 c6 45 }
	condition:
		( uint16(0) == 0x5a4d and filesize < 30KB and all of them )
}