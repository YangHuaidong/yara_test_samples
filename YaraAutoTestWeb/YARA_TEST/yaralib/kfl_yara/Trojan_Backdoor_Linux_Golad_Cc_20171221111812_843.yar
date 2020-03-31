rule Trojan_Backdoor_Linux_Golad_Cc_20171221111812_843 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Linux.Golad.Cc"
		threattype = "BackDoor"
		family = "Golad"
		hacker = "None"
		refer = "7705b32ac794839852844bb99d494797"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-10-26"
	strings:
		$s0 = "46HP5" nocase wide ascii
		$s1 = "NJSJ6" nocase wide ascii
		$s2 = "//wxRB" nocase wide ascii
		$s3 = "6e%9m8" nocase wide ascii

	condition:
		all of them
}
