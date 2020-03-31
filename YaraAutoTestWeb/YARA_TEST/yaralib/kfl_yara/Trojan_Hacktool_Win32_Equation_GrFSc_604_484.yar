rule Trojan_Hacktool_Win32_Equation_GrFSc_604_484
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.GrFSc"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "7c491148af6815a3becea0c011964816"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-20"
        description = "Equation Group hack tool set GrDo_FileScanner_Implant "
	strings:
		$s1 = "system32\\winsrv.dll" fullword wide
		$s2 = "raw_open CreateFile error" fullword ascii
		$s3 = "\\dllcache\\" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 400KB and all of them )
}