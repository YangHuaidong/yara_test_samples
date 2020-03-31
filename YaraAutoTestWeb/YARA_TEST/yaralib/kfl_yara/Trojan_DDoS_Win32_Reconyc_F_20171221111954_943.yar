rule Trojan_DDoS_Win32_Reconyc_F_20171221111954_943 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Reconyc.F"
		threattype = "DDOS"
		family = "Reconyc"
		hacker = "None"
		refer = "e635156b81745ff77b5423c27b55c656"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-08-14"
	strings:
		$s0 = "%s.%s.%s.%d"
		$s1 = "SynFloodThread"
		$s3 = "Address %d : %s"
		$s4 = "Yow! Bad host lookup."
		$s5 = "SynBigFloodThread"
		$s6 = "/c del"

	condition:
		all of them
}
