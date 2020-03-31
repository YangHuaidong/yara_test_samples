rule Trojan_Hacktool_Win32_Equation_EeSRv24_694_455
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.eSRv24"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "1e59862c7b27991c32e189e66af9205b,25a473cc8026465c56893757295f9547,22b6f3ae1a645e7bdf2b20682a1cb55e,f09f7c0818c61d11e80dfa4c519f75d3,a2ee4d67361d146f5c4aaa03e93b85e3"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-09-03"
        description = "Equation Group hack tool set ecwi_ESKE_EVFR_RPC2_2 "
	strings:
		$x1 = "* Listening Post DLL %s() returned error code %d." fullword ascii
		$s1 = "WsaErrorTooManyProcesses" fullword ascii
		$s2 = "NtErrorMoreProcessingRequired" fullword ascii
		$s3 = "Connection closed by remote host (TCP Ack/Fin)" fullword ascii
		$s4 = "ServerErrorBadNamePassword" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 2000KB and all of ($s*) or 1 of ($x*) )
}