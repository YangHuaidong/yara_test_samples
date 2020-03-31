rule Trojan_DDoS_Win32_StormDDoS_6_20161213095151_1028_323 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.StormDDoS.6"
		threattype = "DDOS"
		family = "StormDDoS"
		hacker = "None"
		refer = "0D66B31F0C93E9A6F995FDA7887A1A31"
		description = "Gen_Trojan_Mikey"
		comment = "None"
		author = "Florian Roth"
		date = "2016-06-23"
	strings:
		$s0 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\ERAWTFOS" fullword ascii
		$s1 = "User-Agent:Mozilla/4.0 (compatible; MSIE %d.0; Windows NT %d.1; SV1)" fullword ascii
		$s2 = "User-Agent:Mozilla/4.0 (compatible; MSIE 6.00; Windows NT 5.0; MyIE 3.01)" fullword ascii
		$s3 = "%d*%u%s" fullword ascii
		$s4 = "%s %s:%d" fullword ascii
		$s5 = "Mnopqrst Vwxyabcde Ghijklm Opqrstuv Xya" fullword ascii

	condition:
		uint16(0) == 0x5a4d and $s0 and 2 of ($s*)
}
