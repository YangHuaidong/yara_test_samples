rule Trojan_Hacktool_Win32_Equation_Estdit_479_467
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.Estdit"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "1d2db6d8d77c2e072db34ca7377722be"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-30"
        description = "Equation Group hack tool set EquationGroup_Toolset_Apr17_Esteemaudit_2_1_0 "
	strings:
		$x1 = "[+] Connected to target %s:%d" fullword ascii
		$x2 = "[-] build_exploit_run_x64():" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}