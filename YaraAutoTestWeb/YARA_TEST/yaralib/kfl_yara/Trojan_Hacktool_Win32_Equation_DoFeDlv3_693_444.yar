rule Trojan_Hacktool_Win32_Equation_DoFeDlv3_693_444
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.DoFeDlv3"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "61110bea272972903985d5d5e452802c"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-09-03"
        description = "Equation Group hack tool set DoubleFeatureDll_dll_3 "
	strings:
		$a = { f4 65 c6 45 f5 6c c6 45 f6 33 c6 45 f7 32 c6 45 }
		$b = { 36 c6 45 e6 34 c6 45 e7 50 c6 45 e8 72 c6 45 e9 }
		$c = { c6 45 e8 65 c6 45 e9 70 c6 45 ea 74 c6 45 eb 5f }
	condition:
		( uint16(0) == 0x5a4d and filesize < 1000KB and all of them ) 
}