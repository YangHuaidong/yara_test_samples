rule Trojan_Backdoor_Win32_Sniffer_analyzer_814
{
	meta:
	    judge = "black"
	    threatname = "Trojan[Backdoor]/Win32.Sniffer.analyzer"
	    threattype = "Backdoor"
	    family = "Sniffer"
	    hacker = "None"
	    refer = "20f1eb1aace868b41d067c6806a9e2bf"
	    comment = "None"
		description = "Chinese Hacktool Set - file Sniffer analyzer SSClone 1210 full version.exe"
		author = "Florian Roth -lz"
		date = "2015-06-13"

	strings:
		$s0 = "http://www.vip80000.com/hot/index.html" fullword ascii
		$s1 = "GetConnectString" fullword ascii
		$s2 = "CnCerT.Safe.SSClone.dll" fullword ascii
		$s3 = "(*.JPG;*.BMP;*.GIF;*.ICO;*.CUR)|*.JPG;*.BMP;*.GIF;*.ICO;*.CUR|JPG" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3580KB and all of them
}