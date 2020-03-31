rule Trojan_Hacktool_Win32_Equation_driImp_581_446
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.driImp"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "e5b96113647a0519f750095aa8b111bb"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-08-13"
        description = "Equation Group hack tool set drivers_Implant "
	strings:
		$s1 = ".?AVFeFinallyFailure@@" fullword ascii
		$s2 = "hZwLoadDriver" fullword ascii
		$op1 = { b0 01 e8 58 04 00 00 c3 33 }
	condition:
		( uint16(0) == 0x5a4d and filesize < 30KB and all of them )
}