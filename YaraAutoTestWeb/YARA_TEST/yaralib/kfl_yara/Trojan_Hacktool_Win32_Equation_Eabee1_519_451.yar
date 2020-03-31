rule Trojan_Hacktool_Win32_Equation_Eabee1_519_451
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.Eabee1"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "2dee8e8fccd2407677fbcde415fdf27e"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-30"
        description = "Equation Group hack tool set Easybee_1_0_1 "
	strings:
		$x1 = "@@for /f \"delims=\" %%i in ('findstr /smc:\"%s\" *.msg') do if not \"%%MsgFile1%%\"==\"%%i\" del /f \"%%i\"" fullword ascii
		$x2 = "Logging out of WebAdmin (as target account)" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}