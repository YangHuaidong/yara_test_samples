rule Trojan_Hacktool_Win32_Equation_DsImpl_601_447
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.DsImpl"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "54dec8d0fe7036f8acc7b6e06b494b0b,7f580643ee9b45fb0685a4ead0a3de34"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-20"
        description = "Equation Group hack tool set Dsz_Implant "
	strings:
		$s1 = "%02u:%02u:%02u.%03u-%4u: " fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 1000KB and all of them )
}