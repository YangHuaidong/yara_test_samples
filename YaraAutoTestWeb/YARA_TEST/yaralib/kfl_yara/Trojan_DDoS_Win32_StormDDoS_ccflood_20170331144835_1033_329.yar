rule Trojan_DDoS_Win32_StormDDoS_ccflood_20170331144835_1033_329 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.StormDDoS.ccflood"
		threattype = "DDOS"
		family = "StormDDoS"
		hacker = "None"
		refer = "80cc35770104e1e526575d42ec68daf2"
		description = "None"
		comment = "None"
		author = "sxy"
		date = "2017-03-23"
	strings:
		$s0 = "%c%c%c%c%c%c.exe"
		$s1 = "cc flood"
		$s2 = "/c del"
		$s3 = "GET %s HTTP/1.1"
		$s4 = "Host: %s:%d"

	condition:
		all of them
}
