rule Trojan_DDoS_Win32_StormDDoS_fack_20170331144836_1034_330 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.StormDDoS.fack"
		threattype = "DDOS"
		family = "StormDDoS"
		hacker = "None"
		refer = "df814c1b62c536a5038bd8e08187117e,6542c65a4e6fd7860f94f8865fe80a45,be6423e9145ade2a22ba6b16595a650f"
		description = "None"
		comment = "None"
		author = "sxy"
		date = "2017-03-23"
	strings:
		$s0 = "fack.dat"
		$s1 = "Newtest"
		$s2 = "%s\\shell\\open\\%s"
		$s3 = "%s.dll"

	condition:
		all of them
}
