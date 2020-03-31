rule Trojan_Hacktool_Win32_Equation_Smbtou_481_520
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.Smbtou"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "b50fff074764b3a29a00b245e4d0c863"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-30"
        description = "Equation Group hack tool set EquationGroup_Toolset_Apr17_Smbtouch_1_1_1 "
	strings:
		$x1 = "[+] Target is vulnerable to %d exploit%s" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 400KB and all of them )
}