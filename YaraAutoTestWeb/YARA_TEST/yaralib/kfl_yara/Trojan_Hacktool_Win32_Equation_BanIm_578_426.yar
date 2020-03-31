rule Trojan_Hacktool_Win32_Equation_BanIm_578_426
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.BanIm"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "2aa7537077a2547765c2b09d00f0f173"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-08-13"
        description = "Equation Group hack tool set Banner_Implant9x "
	strings:
		$s1 = ".?AVFeFinallyFailure@@" fullword ascii
		$op1 = { c9 c3 57 8d 85 2c eb ff ff }
	condition:
      ( uint16(0) == 0x5a4d and filesize < 20KB and all of them )
}