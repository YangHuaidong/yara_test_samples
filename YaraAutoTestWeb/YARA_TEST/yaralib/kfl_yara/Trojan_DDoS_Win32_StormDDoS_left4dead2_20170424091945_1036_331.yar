rule Trojan_DDoS_Win32_StormDDoS_left4dead2_20170424091945_1036_331 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.StormDDoS.left4dead2"
		threattype = "DDOS"
		family = "StormDDoS"
		hacker = "None"
		refer = "9ce80c5323c8b13f1fe8bc3cf4041639"
		description = "None"
		comment = "None"
		author = "sxy"
		date = "2017-04-11"
	strings:
		$s0 = "left4dead2.exe"
		$s1 = "NDOWS\\TEMP\\nsf1.tmp"
		$s2 = "Name Setup"
		$s3 = "Safengine Shielden v2.3.3.0"
		$s4 = "%u.%u%s%s"
		$s5 = "4dead2-ori.exe"

	condition:
		5 of them
}
