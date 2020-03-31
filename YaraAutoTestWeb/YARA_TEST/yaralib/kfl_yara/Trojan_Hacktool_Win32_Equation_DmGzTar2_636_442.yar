rule Trojan_Hacktool_Win32_Equation_DmGzTar2_636_442
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.DmGzTar2"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "fbe384d937ca976a64d97ae0cb06aabb"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-20"
        description = "Equation Group hack tool set DmGz_Target_2 "
	strings:
		$s1 = "\\\\.\\%ls" fullword ascii
		$op0 = { e8 ce 34 00 00 b8 02 00 00 f0 e9 26 02 00 00 48 }
		$op1 = { 8b 4d 28 e8 02 05 00 00 89 45 34 eb 07 c7 45 34 }
		$op2 = { e8 c2 34 00 00 90 48 8d 8c 24 00 01 00 00 e8 a4 }
	condition:
		( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}