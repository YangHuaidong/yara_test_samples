rule Trojan_Hacktool_Win32_Equation_pImp9_611_501
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.pImp9"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "3b6beff71b032860e3805b1bcd4a4d5d"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-20"
        description = "Equation Group hack tool set put_Implant9x "
	strings:
		$s1 = "3&3.3<3A3F3K3V3c3m3" fullword ascii
		$op1 = { c9 c2 08 00 b8 72 1c 00 68 e8 c9 fb ff ff 51 56 }
		$op2 = { 40 1b c9 23 c8 03 c8 38 5d 14 74 05 6a 03 58 eb }
	condition:
		( uint16(0) == 0x5a4d and filesize < 20KB and 2 of them )
}