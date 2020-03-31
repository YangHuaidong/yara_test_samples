rule Trojan_DDoS_Win32_StormDDoS_service_20170331144838_1043_338 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.StormDDoS.service"
		threattype = "DDOS"
		family = "StormDDoS"
		hacker = "None"
		refer = "9ce80c5323c8b13f1fe8bc3cf4041639"
		description = "None"
		comment = "None"
		author = "sxy"
		date = "2017-03-23"
	strings:
		$s0 = "Host: %s:%d"
		$s1 = "%s %s %s%d"
		$s3 = "%c%c%c%c%c%c.exe"
		$s4 = "Connection: Keep-Alive"
		$s5 = "%s%s%s%s%s%s%s%s%s%s%s"
		$s6 = "%d.%d.%d.%d"
		$s7 = "GET %s HTTP/1.1"
		$s8 = "URLDownloadToFileA"
		$s9 = "lpk"
		$s10 = "DNSFlood"
		$a0 = "Pqrstu Wxyabcde Ghi"
		$a1 = "Fghijk Mnopqrst Vwx"
		$a2 = "Ghijkl Nopqrsstu Wxy"
		$a3 = "Stuvwx Abcdefgh Jkl"

	condition:
		(5 of ($s*) and 1 of ($a*))
}
