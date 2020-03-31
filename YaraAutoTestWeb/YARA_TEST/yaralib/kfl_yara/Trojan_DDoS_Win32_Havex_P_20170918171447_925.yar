rule Trojan_DDoS_Win32_Havex_P_20170918171447_925 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Havex.P"
		threattype = "DDOS"
		family = "Havex"
		hacker = "None"
		refer = "780b373d6a36de674aa4c7a262e2124f"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-09-08"
	strings:
		$s0 = "bzip2/libbzip2"
		$s1 = "jseward@bzip.org"
		$s3 = "havex"
		$s4 = { 73 00 74 00 61 00 6c 00 70 00 72 00 6f 00 66 00 2e 00 63 00 6f 00 6d 00 2e 00 75 00 61 }
		$s5 = { 77 00 77 00 77 00 2e 00 63 00 6f 00 6d 00 65 00 74 00 6f 00 74 00 68 00 65 00 74 00 72 00 75 00 74 00 68 00 2e 00 63 00 6f 00 6d }

	condition:
		all of them
}
