rule Trojan_Backdoor_Win32_Destover_A_20161213095223_903_54 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Destover.A"
		threattype = "rat"
		family = "Destover"
		hacker = "None"
		refer = "760c35a80d758f032d02cf4db12d3e55"
		description = "unknown_wiper_error_strings"
		comment = "None"
		author = "None"
		date = "2016-06-23"
	strings:
		$s0 = "203.131.222.102" fullword nocase
		$s1 = "217.96.33.164" fullword nocase
		$s2 = "88.53.215.64" fullword nocase

	condition:
		all of them
}
