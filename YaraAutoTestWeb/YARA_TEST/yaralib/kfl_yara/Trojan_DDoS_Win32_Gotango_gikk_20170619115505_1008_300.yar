rule Trojan_DDoS_Win32_Gotango_gikk_20170619115505_1008_300 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Gotango.gikk"
		threattype = "DDOS"
		family = "Gotango"
		hacker = "none"
		refer = "a382ab00b957e4400a7409920dec6121"
		description = "None"
		comment = "none"
		author = "xc"
		date = "2017-06-15"
	strings:
		$s0 = "wscript.exe"
		$s1 = "aIg.exe"
		$s2 = "ping 127.0.01 -n 10&start"
		$s3 = "123.184.40.33"
		$s4 = "9981"

	condition:
		all of them
}
