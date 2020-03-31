rule Trojan_Hacktool_Win32_Equation_Edusch_475_454
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.Edusch"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "0bc136522423099f72dbf8f67f99e7d8"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-30"
        description = "Equation Group hack tool set EquationGroup_Toolset_Apr17_Educatedscholar_1_0_0 "
	strings:
		$x1 = "[+] Shellcode Callback %s:%d" fullword ascii
		$x2 = "[+] Exploiting Target" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 150KB and 1 of them )
}