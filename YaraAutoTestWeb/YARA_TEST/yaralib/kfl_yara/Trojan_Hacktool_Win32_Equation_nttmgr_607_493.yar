rule Trojan_Hacktool_Win32_Equation_nttmgr_607_493
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.nttmgr"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "05cee4ff15a0f7fa2583982b25cc2969,0d81f9972863c6d8c90100a73b0600ab,a01d34e3ede607849bb73bced216ac0a"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-20"
        description = "Equation Group hack tool set ntfltmgr "
	strings:
		$s3 = "wCw3wDwAw2wNw@wEwZw2wDwEwBwZwFwFw4w2wZw5w1w4wFwZwGwOwGwGwEw5w2wFwGwDwFwOw" fullword ascii
		$s6 = "w+w;w2w0w6w4w.w(wRw" fullword ascii
		$op1 = { 80 f7 ff ff 49 89 84 34 18 02 00 00 41 83 a4 34 }
		$op2 = { ff 15 0b 34 00 00 eb 92 }
		$op3 = { 4d 8d b4 34 08 02 00 00 4d 85 f6 0f 84 ae }
		$op4 = { 8b ca 2b ce 8d 34 01 0f b7 3e 66 3b 7d f0 89 75 }
		$op5 = { 8a 40 01 00 c7 47 70 }
		$op6 = { e9 3c ff ff ff 6a ff 8d 45 f0 50 e8 27 11 00 00 }
		$op7 = { 8b 45 08 53 57 8b 7d 0c c7 40 34 }
	condition:
		( uint16(0) == 0x5a4d and filesize < 100KB and 4 of them )
}