rule Trojan_Hacktool_Win32_Equation_EREFv11_695_459
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.EREFv11"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "e62f9433faa7b33c7856e8b30b69b698,ea147f8bf6e4fc490b8a92478ea247e4,c716ad40c0aaef9b936595ba1e9365cd,22b6f3ae1a645e7bdf2b20682a1cb55e,f09f7c0818c61d11e80dfa4c519f75d3"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-09-03"
        description = "Equation Group hack tool set ELV_ESKE_ETBL_ETRE_EVFR_11 "
	strings:
		$x1 = "Target is vulnerable" fullword ascii
		$x2 = "Target is NOT vulnerable" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them )
}