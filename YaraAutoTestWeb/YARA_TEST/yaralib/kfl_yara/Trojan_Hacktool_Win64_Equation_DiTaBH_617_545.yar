rule Trojan_Hacktool_Win64_Equation_DiTaBH_617_545
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win64.Equation.DiTaBH"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "bdaecf71797f674f3c280866d2a1205c"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-20"
        description = "Equation Group hack tool set DiBa_Target_BH "
	strings:
		$op0 = { 44 89 20 e9 40 ff ff ff 8b c2 48 8b 5c 24 60 48 }
		$op1 = { 45 33 c9 49 8d 7f 2c 41 ba }
		$op2 = { 89 44 24 34 eb 17 4c 8d 44 24 28 8b 54 24 30 48 }
	condition:
		( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}