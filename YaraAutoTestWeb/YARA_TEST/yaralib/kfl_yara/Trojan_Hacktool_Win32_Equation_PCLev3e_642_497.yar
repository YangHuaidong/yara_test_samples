rule Trojan_Hacktool_Win32_Equation_PCLev3e_642_497
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.PCLev3e"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "ef07e27c10fbf572a0460b03867adf09"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-27"
        description = "Equation Group hack tool set PC_Level3_http_exe "
	strings:
		$s1 = "Copyright (C) Microsoft" fullword wide
		$op1 = { 24 39 65 c6 44 24 3a 6c c6 44 24 3b 65 c6 44 24 }
		$op2 = { 44 24 4e 41 88 5c 24 4f ff }
		$op3 = { 44 24 3f 6e c6 44 24 40 45 c6 44 24 41 }
	condition:
		( uint16(0) == 0x5a4d and filesize < 400KB and all of them )
}	