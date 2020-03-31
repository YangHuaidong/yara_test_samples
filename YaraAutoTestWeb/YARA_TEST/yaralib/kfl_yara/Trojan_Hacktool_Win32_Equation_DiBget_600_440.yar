rule Trojan_Hacktool_Win32_Equation_DiBget_600_440
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.DiBget"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "7b631b6dab156a47f085f4abe4b2acfe"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-20"
        description = "Equation Group hack tool set DiBa_Target "
	strings:
		$op1 = { 41 5a 41 59 41 58 5f 5e 5d 5a 59 5b 58 48 83 c4 }
		$op2 = { f9 48 03 fa 48 33 c0 8a 01 49 03 c1 49 f7 e0 88 }
		$op3 = { 01 41 f6 e0 49 03 c1 88 01 48 33 }
	condition:
		( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}