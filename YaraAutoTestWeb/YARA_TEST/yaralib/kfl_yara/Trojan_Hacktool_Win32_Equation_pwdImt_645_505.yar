rule Trojan_Hacktool_Win32_Equation_pwdImt_645_505
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.pwdImt"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "8d439c80fd2c80213b9964c5bf6e9e71"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-27"
        description = "Equation Group hack tool set pwd_Implant "
	strings:
		$s1 = "7\"7(7/7>7O7]7o7w7" fullword ascii
		$op1 = { 40 50 89 44 24 18 FF 15 34 20 00 }
	condition:
		( uint16(0) == 0x5a4d and filesize < 20KB and 1 of them )
}	