rule Trojan_Backdoor_Win32_Industroyer_Portscan_1161
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Industroyer.Portscan"
		threattype = "ICS,Backdoor"
		family = "Industroyer"
		hacker = "None"
		refer = "497de9d388d23bf8ae7230d80652af69"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-03-21"
		description = "https://github.com/Yara-Rules/rules/blob/master/malware/APT_Industroyer.yar"
	strings:
		$s1 = "!ZBfamily" fullword ascii
		$s2 = ":g/outddomo;" fullword ascii
		$s3 = "GHIJKLMNOTST" fullword ascii
		/* Decompressed File */
		$d1 = "Error params Arguments!!!" fullword wide
		$d2 = "^(.+?.exe).*\\s+-ip\\s*=\\s*(.+)\\s+-ports\\s*=\\s*(.+)$" fullword wide
		$d3 = "Exhample:App.exe -ip= 127.0.0.1-100," fullword wide
		$d4 = "Error IP Range %ls - %ls" fullword wide
		$d5 = "Can't closesocket." fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 500KB and all of ($s*) or 2 of ($d*) )
}