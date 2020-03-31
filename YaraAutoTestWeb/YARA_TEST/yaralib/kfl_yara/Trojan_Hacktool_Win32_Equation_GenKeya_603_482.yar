rule Trojan_Hacktool_Win32_Equation_GenKeya_603_482
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.GenKeya"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "0b9b4388dd9dc4f696cba7b0181a2640"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-20"
        description = "Equation Group hack tool set GenKey "
	strings:
		$x1 = "* PrivateEncrypt -> PublicDecrypt FAILED" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 80KB and all of them )
}