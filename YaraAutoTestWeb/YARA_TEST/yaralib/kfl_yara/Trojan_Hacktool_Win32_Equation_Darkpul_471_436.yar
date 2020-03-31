rule Trojan_Hacktool_Win32_Equation_Darkpul_471_436
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.Darkpul"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "05f8f70d2ef15a375d4d9dee14072404"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-30"
        description = "Equation Group hack tool set EquationGroup_Toolset_Apr17_Darkpulsar_1_1_0 "
	strings:
		$x1 = "[%s] - Error upgraded DLL architecture does not match target architecture (0x%x)" fullword ascii
		$x2 = "[%s] - Error building DLL loading shellcode" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}