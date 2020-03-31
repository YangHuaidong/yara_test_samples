rule Trojan_Hacktool_Win32_Equation_GanThiefIm_639_477
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.GanThiefIm"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "0a15d5db34a7f30642dfeffc5d515d94"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-27"
        description = "Equation Group hack tool set EquationGroup_Toolset_Apr17_GangsterThief_Implant "
	strings:
		$s1 = "\\\\.\\%s:" fullword wide
		$s4 = "raw_open CreateFile error" fullword ascii
		$s5 = "-PATHDELETED-" fullword ascii
		$s6 = "(deleted)" fullword wide
		$s8 = "NULLFILENAME" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 300KB and 3 of them )
}