rule Trojan_Hacktool_Win32_Equation_renamer_614_511
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.renamer"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "7956771bacb5982ec105d8581509b639"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-20"
        description = "Equation Group hack tool set renamer "
	strings:
		$s1 = "FILE_NAME_CONVERSION.LOG" fullword wide
		$s2 = "Log file exists. You must delete it!!!" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 80KB and all of them )
}