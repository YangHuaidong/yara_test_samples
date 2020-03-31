rule Trojan_Hacktool_Win32_Equation_msgksgu_606_489
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.msgksgu"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "9dab2f84eb817aab4ccf8c237f88b422,a54f0112500c956c21dc13285f43fc7e"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-20"
        description = "Equation Group hack tool set msgks_mskgu "
	strings:
		$op1 = { f4 65 c6 45 f5 6c c6 45 f6 33 c6 45 f7 32 c6 45 }
		$op2 = { 36 c6 45 e6 34 c6 45 e7 50 c6 45 e8 72 c6 45 e9 }
		$op3 = { c6 45 e8 65 c6 45 e9 70 c6 45 ea 74 c6 45 eb 5f }
	condition:
		( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}