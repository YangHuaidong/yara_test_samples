rule Trojan_Hacktool_Win32_Equation_ETREv10_700_470
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.ETREv10"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "e62f9433faa7b33c7856e8b30b69b698,ea147f8bf6e4fc490b8a92478ea247e4"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-09-03"
        description = "Equation Group hack tool set ETBL_ETRE_10 "
	strings:
		$x1 = "Probe #2 usage: %s -i TargetIp -p TargetPort -r %d [-o TimeOut] -t Protocol -n IMailUserName -a IMailPassword" fullword ascii
		$x6 = "** RunExploit ** - EXCEPTION_EXECUTE_HANDLER : 0x%08X" fullword ascii
		$s19 = "Sending Implant Payload.. cEncImplantPayload size(%d)" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}