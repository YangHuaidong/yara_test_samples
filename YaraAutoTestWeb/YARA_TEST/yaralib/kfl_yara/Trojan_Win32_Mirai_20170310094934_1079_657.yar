rule Trojan_Win32_Mirai_20170310094934_1079_657 
{
	meta:
		judge = "black"
		threatname = "Trojan/Win32.Mirai"
		threattype = "DDOS"
		family = "Mirai"
		hacker = "None"
		refer = "93ccd8225c8695cade5535726b0dd0b6"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-02-27"
	strings:
		$s1 = "c:\\windows\\system"
		$s2 = "c:\\windows\\system\\msinfo.exe"
		$s3 = "/delete /f /tn msinfo"
		$s4 = "upslist.txt"
		$s5 = "update.txt"
		$s6 = "DhcpIPAddress"
		$s7 = "NameServer"
		$s8 = "SubnetMask"
		$s9 = "ver.txt"

	condition:
		all of them
}
