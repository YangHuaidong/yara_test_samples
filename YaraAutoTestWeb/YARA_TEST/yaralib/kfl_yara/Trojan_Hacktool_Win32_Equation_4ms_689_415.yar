rule Trojan_Hacktool_Win32_Equation_4ms_689_415
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.4ms"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "bc8881535f5403af2b45ffceee0a0fbb,bd771e0fc59353f662d2f36f39f6724b,62e9f059c4889bf28170cae9cdbd8a1a,45a47b88077fcb9aaed61f2aea836eed,ad265a017a618fb4c38fde4c33dbf085"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-09-03"
        description = "Equation Group hack tool set msgkd_msslu64_msgki_mssld "
	strings:
		$s1 = "PQRAPAQSTUVWARASATAUAVAW" fullword ascii
		$s2 = "SQRUWVAWAVAUATASARAQAP" fullword ascii
		$s3 = "iijymqp" fullword ascii
		$s4 = "AWAVAUATASARAQI" fullword ascii
		$s5 = "WARASATAUAVM" fullword ascii
		$op1 = { 0c 80 30 02 48 83 c2 01 49 83 e9 01 75 e1 c3 cc }
		$op2 = { e8 10 66 0d 00 80 66 31 02 48 83 c2 02 49 83 e9 }
		$op3 = { 48 b8 53 a5 e1 41 d4 f1 07 00 48 33 }
	condition:
		( uint16(0) == 0x5a4d and filesize < 1000KB and 2 of ($s*) or all of ($op*) )
}