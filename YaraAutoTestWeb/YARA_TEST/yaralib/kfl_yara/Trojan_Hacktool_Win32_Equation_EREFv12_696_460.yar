rule Trojan_Hacktool_Win32_Equation_EREFv12_696_460
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.EREFv12"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "115b9731f960bf5863afbaf600bfa407,c716ad40c0aaef9b936595ba1e9365cd,22b6f3ae1a645e7bdf2b20682a1cb55e,f09f7c0818c61d11e80dfa4c519f75d3"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-09-03"
        description = "Equation Group hack tool set ELV_ESKE_EVFR_RideArea2_12 "
	strings:
		$x2 = "** CreatePayload ** - EXCEPTION_EXECUTE_HANDLER" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}