rule Trojan_Hacktool_Win32_Equation_DFeatDll2_634_437
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.DFeatDll2"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "d41df517d60ed2ef7edebb4db9b9dc19,b3196517e084ea05dc6eaff231be9676,58bfa2eb639850ebfeced55cac3e82fb"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-20"
        description = "Equation Group hack tool set DoubleFeatureDll_dll_2 "
	strings:
		$s1 = ".dllfD" fullword ascii
		$s2 = "Khsppxu" fullword ascii
		$s3 = "D$8.exe" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 1000KB and 2 of them )
}