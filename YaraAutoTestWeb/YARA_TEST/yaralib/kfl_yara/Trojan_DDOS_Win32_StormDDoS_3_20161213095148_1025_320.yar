rule Trojan_DDOS_Win32_StormDDoS_3_20161213095148_1025_320 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDOS]/Win32.StormDDoS.3"
		threattype = "DDOS"
		family = "StormDDoS"
		hacker = "None"
		refer = "F052FD3A2D277E93A84D97499218118A,532AE6AAF86A54AF362963639BF91BB9"
		description = "Nitol"
		comment = "None"
		author = "dengcong<admin@antiy.cn>"
		date = "2016-11-22"
	strings:
		$s0 = "%c%c%c%c%c%c.exe"
		$s1 = "~MHz"
		$s2 = "COMSPEC"
		$s3 = "CCAttack"
		$s4 = "TCPConnectFloodThread"

	condition:
		3 of them
}
