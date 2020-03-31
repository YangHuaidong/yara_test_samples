rule Trojan_Hacktool_Win32_Equation_eSRv22_699_466
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.eSRv22"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "25a473cc8026465c56893757295f9547,22b6f3ae1a645e7bdf2b20682a1cb55e,f09f7c0818c61d11e80dfa4c519f75d3,a2ee4d67361d146f5c4aaa03e93b85e3"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-09-03"
        description = "Equation Group hack tool set ecwi_ESKE_EVFR_RPC2_2 "
	strings:
		$s1 = "Target is share name" fullword ascii
		$s2 = "Could not make UdpNetbios header -- bailing" fullword ascii
		$s3 = "Request non-NT session key" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}