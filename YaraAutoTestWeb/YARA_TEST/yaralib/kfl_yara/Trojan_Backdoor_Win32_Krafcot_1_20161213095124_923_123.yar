rule Trojan_Backdoor_Win32_Krafcot_1_20161213095124_923_123 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Krafcot.1"
		threattype = "rat"
		family = "Krafcot"
		hacker = "None"
		refer = "31A9611A922813BB28BCA22452DB1E18"
		description = "None"
		comment = "None"
		author = "felicity_chou"
		date = "2016-06-23"
	strings:
		$s0 = "TFN:%s:%d"
		$s1 = "sd error"
		$s2 = "Beizhu"
		$s3 = "/c del"
		$s4 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"
		$s5 = "dhn:%s"

	condition:
		4 of them
}
