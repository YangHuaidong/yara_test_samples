rule Trojan_Backdoor_Win32_Industroyer_c_1160
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Industroyer.c"
		threattype = "ICS,Backdoor"
		family = "Industroyer"
		hacker = "None"
		refer = "f9005f8e9d9b854491eb2fbbd06a16e0"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-03-21"
		description = "https://github.com/Yara-Rules/rules/blob/master/malware/APT_Industroyer.yar"
	strings:
		$s1 = "haslo.dat" fullword wide
		$s2 = "defragsvc" fullword ascii
		/* .dat\x00\x00Crash */
		$a1 = { 00 2E 00 64 00 61 00 74 00 00 00 43 72 61 73 68 00 00 00 }
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and all of ($s*) or $a1 )
}