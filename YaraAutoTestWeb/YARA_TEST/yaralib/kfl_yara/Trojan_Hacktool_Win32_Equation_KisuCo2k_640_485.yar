rule Trojan_Hacktool_Win32_Equation_KisuCo2k_640_485
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.KisuCo2k"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "e7ce87de5dc950ea389fab01ae69fe19"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-27"
        description = "Equation Group hack tool set KisuComms_Target_2000 "
	strings:
		$s1 = "363<3S3c3l3q3v3{3" fullword ascii
		$s2 = "3!3%3)3-3135393@5" fullword ascii
		/* Recommendation - verify the opcodes on Binarly : http://www.binar.ly */
		/* Test each of them in the search field & reduce length until it generates matches */
		$op0 = { eb 03 89 46 54 47 83 ff 1a 0f 8c 40 ff ff ff 8b }
		$op1 = { 8b 46 04 85 c0 74 0f 50 e8 34 fb ff ff 83 66 04 }
		$op2 = { c6 45 fc 02 8d 8d 44 ff ff ff e8 d2 2f 00 00 eb }
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and ( all of ($s*) or all of ($op*) ) )
}	