rule Trojan_Backdoor_Win32_PcClient_af_813
{
	meta:
	    judge = "black"
	    threatname = "Trojan[Backdoor]/Win32.PcClient.af"
	    threattype = "Backdoor"
	    family = "PcClient"
	    hacker = "None"
	    refer = "c30f55ba0f84a50dfbb4de7b68dc6537"
	    comment = "None"
		description = "Chinese Hacktool Set - file PcInit.exe"
		author = "Florian Roth -lz"
		date = "2015-06-13"

	strings:
		$s1 = "\\svchost.exe" fullword ascii
		$s2 = "%s%08x.001" fullword ascii
		$s3 = "Global\\ps%08x" fullword ascii
		$s4 = "drivers\\" fullword ascii /* Goodware String - occured 2 times */
		$s5 = "StrStrA" fullword ascii /* Goodware String - occured 43 times */
		$s6 = "StrToIntA" fullword ascii /* Goodware String - occured 44 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 50KB and all of them
}