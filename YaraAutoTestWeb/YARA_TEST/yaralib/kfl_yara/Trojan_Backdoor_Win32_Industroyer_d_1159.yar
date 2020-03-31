rule Trojan_Backdoor_Win32_Industroyer_c_1159
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Industroyer.c"
		threattype = "ICS,Backdoor"
		family = "Industroyer"
		hacker = "None"
		refer = "a193184e61e34e2bc36289deaafdec37"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-03-21"
		description = "https://github.com/Yara-Rules/rules/blob/master/malware/APT_Industroyer.yar"
	strings:
		$x1 = "D2MultiCommService.exe" fullword ascii
		$x2 = "Crash104.dll" fullword ascii
		$x3 = "iec104.log" fullword ascii
		$x4 = "IEC-104 client: ip=%s; port=%s; ASDU=%u " fullword ascii

		$s1 = "Error while getaddrinfo executing: %d" fullword ascii
		$s2 = "return info-Remote command" fullword ascii
		$s3 = "Error killing process ..." fullword ascii
		$s4 = "stop_comm_service_name" fullword ascii
		$s5 = "*1* Data exchange: Send: %d (%s)" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 400KB and ( 1 of ($x*) or 4 of them ) ) or ( all of them )
}