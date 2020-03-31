rule Trojan_DDoS_Win32_Reconyc_F_803
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Reconyc.F"
		threattype = "DDoS"
		family = "Reconyc"
		hacker = "None"
		refer = "e635156b81745ff77b5423c27b55c656"
		author = "HuangYY"
		comment = "None"
		date = "2017-08-14"
		description = "None"

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