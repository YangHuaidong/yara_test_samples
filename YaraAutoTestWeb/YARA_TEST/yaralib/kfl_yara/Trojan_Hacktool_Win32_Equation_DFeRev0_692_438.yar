rule Trojan_Hacktool_Win32_Equation_DFeRev0_692_438
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.DFeRev0"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "48094800e01e92034bfdc930bf0e33a0,16722e9d2fff6550a96175028c3d8856"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-09-03"
        description = "Equation Group hack tool set DoubleFeatureReader_DoubleFeatureReader_0 "
	strings:
		$x1 = "DFReader.exe logfile AESKey [-j] [-o outputfilename]" fullword ascii
		$x2 = "Double Feature Target Version" fullword ascii
		$x3 = "DoubleFeature Process ID" fullword ascii
		$op1 = { a1 30 21 41 00 89 85 d8 fc ff ff a1 34 21 41 00 }
	condition:
		( uint16(0) == 0x5a4d and filesize < 300KB and 1 of them ) or ( 2 of them )
}