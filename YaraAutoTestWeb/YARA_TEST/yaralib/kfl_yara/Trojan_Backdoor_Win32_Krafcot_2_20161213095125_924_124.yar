rule Trojan_Backdoor_Win32_Krafcot_2_20161213095125_924_124 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Krafcot.2"
		threattype = "rat"
		family = "Krafcot"
		hacker = "None"
		refer = "31A9611A922813BB28BCA22452DB1E18"
		description = "None"
		comment = "None"
		author = "felicity_chou"
		date = "2016-06-23"
	strings:
		$s0 = "Socket Setup Error..."
		$s1 = "dhn:%s"
		$s2 = "sd error"
		$s3 = "/c del"
		$s4 = "%s%d.exe"

	condition:
		3 of them
}
