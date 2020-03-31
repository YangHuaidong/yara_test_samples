rule Trojan_Hacktool_Win32_Equation_EVFRv16_702_472
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.EVFRv16"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "c716ad40c0aaef9b936595ba1e9365cd,22b6f3ae1a645e7bdf2b20682a1cb55e,f09f7c0818c61d11e80dfa4c519f75d3"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-09-03"
        description = "Equation Group hack tool set ELV_ESKE_EVFR_16 "
	strings:
		$x1 = "ERROR: TbMalloc() failed for encoded exploit payload" fullword ascii
		$x2 = "** EncodeExploitPayload ** - EXCEPTION_EXECUTE_HANDLER" fullword ascii
		$x4 = "** RunExploit ** - EXCEPTION_EXECUTE_HANDLER" fullword ascii
		$s6 = "Sending Implant Payload (%d-bytes)" fullword ascii
		$s7 = "ERROR: Encoder failed on exploit payload" fullword ascii
		$s11 = "ERROR: VulnerableOS() != RET_SUCCESS" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them )
}	