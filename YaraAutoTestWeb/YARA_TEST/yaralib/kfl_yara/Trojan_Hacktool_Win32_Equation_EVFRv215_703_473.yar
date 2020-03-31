rule Trojan_Hacktool_Win32_Equation_EVFRv215_703_473
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.EVFRv215"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "c716ad40c0aaef9b936595ba1e9365cd,22b6f3ae1a645e7bdf2b20682a1cb55e,f09f7c0818c61d11e80dfa4c519f75d3,a2ee4d67361d146f5c4aaa03e93b85e3"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-09-03"
        description = "Equation Group hack tool set ELV_ESKE_EVFR_RPC2_15 "
	strings:
		$x1 = "** SendAndReceive ** - EXCEPTION_EXECUTE_HANDLER" fullword ascii
		$s8 = "Binding to RPC Interface %s over named pipe" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them )
}	