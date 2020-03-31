rule Trojan_Ransomware_Win32_BadRabbit_Mimikatz_1086
{
	meta:
		judge = "black"
		threatname = "Trojan[Ransomware]/Win32.BadRabbit.Mimikatz"
		threattype = "ICS,Ransomware"
		family = "BadRabbit"
		hacker = "None"
		refer = "37945c44a897aa42a66adcab68f560e0"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-03-21"
		description = "https://github.com/Neo23x0/signature-base/blob/master/yara/crime_badrabbit.yar"
	strings:
		$s1 = "%lS%lS%lS:%lS" fullword wide
		$s2 = "lsasrv" fullword wide
		$s3 = "CredentialKeys" ascii
		/* Primary\x00m\x00s\x00v */
		$s4 = { 50 72 69 6D 61 72 79 00 6D 00 73 00 76 00 }
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and 3 of them )
}