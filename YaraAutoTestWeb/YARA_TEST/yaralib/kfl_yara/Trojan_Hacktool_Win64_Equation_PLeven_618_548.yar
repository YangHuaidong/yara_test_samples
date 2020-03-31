rule Trojan_Hacktool_Win64_Equation_PLeven_618_548
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win64.Equation.PLeven"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "e0ad9497d827ff2f532ec683ba78f5d8,8c07421bbc4a2d37da6167118841282c"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-20"
        description = "Equation Group hack tool set PC_Level3_Gen "
	strings:
		$s1 = "S-%u-%u" fullword ascii
		$s2 = "Copyright (C) Microsoft" fullword wide
		$op1 = { 24 39 65 c6 44 24 3a 6c c6 44 24 3b 65 c6 44 24 }
		$op2 = { 44 24 4e 41 88 5c 24 4f ff }
		$op3 = { 44 24 3f 6e c6 44 24 40 45 c6 44 24 41 }
	condition:
		( uint16(0) == 0x5a4d and filesize < 400KB and 3 of them )
}