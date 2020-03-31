rule Trojan_DDoS_Win32_Ramnit_20170717153355_1017_312 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Ramnit"
		threattype = "DDOS"
		family = "Ramnit"
		hacker = "None"
		refer = "e65d17d939d805ceafa55e63c4e403b2"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-06-30"
	strings:
		$s0 = "SSynFloodThread"
		$s1 = "SynBigFloodThread"
		$s2 = "Srv.exe"
		$s3 = "%s.%s.%s.%d "
		$s4 = "Received/sec"
		$s5 = "Sent/sec"

	condition:
		all of them
}
