rule Trojan_Backdoor_Win32_Industroyer_b_1080
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Industroyer.b"
		threattype = "ICS,Backdoor"
		family = "Industroyer"
		hacker = "None"
		refer = "11a67ff9ad6006bd44f08bcc125fb61e"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-03-21"
		description = "https://github.com/Yara-Rules/rules/blob/master/malware/APT_Industroyer.yar"
	strings:
		$x1 = "sc create %ls type= own start= auto error= ignore binpath= \"%ls\" displayname= \"%ls\"" fullword wide
		$x2 = "10.15.1.69:3128" fullword wide
		
		$s1 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; InfoPath.1)" fullword wide
		$s2 = "/c sc stop %s" fullword wide
		$s3 = "sc start %ls" fullword wide
		$s4 = "93.115.27.57" fullword wide
		$s5 = "5.39.218.152" fullword wide
		$s6 = "tierexe" fullword wide
		$s7 = "comsys" fullword wide
		$s8 = "195.16.88.6" fullword wide
		$s9 = "TieringService" fullword wide
		
		$a1 = "TEMP\x00\x00DEF" fullword wide
		$a2 = "TEMP\x00\x00DEF-C" fullword wide
		$a3 = "TEMP\x00\x00DEF-WS" fullword wide
		$a4 = "TEMP\x00\x00DEF-EP" fullword wide
		$a5 = "TEMP\x00\x00DC-2-TEMP" fullword wide
		$a6 = "TEMP\x00\x00DC-2" fullword wide
		$a7 = "TEMP\x00\x00CES-McA-TEMP" fullword wide
		$a8 = "TEMP\x00\x00SRV_WSUS" fullword wide
		$a9 = "TEMP\x00\x00SRV_DC-2" fullword wide
		$a10 = "TEMP\x00\x00SCE-WSUS01" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 300KB and 1 of ($x*) or 3 of them or 1 of ($a*) ) or ( 5 of them )
}