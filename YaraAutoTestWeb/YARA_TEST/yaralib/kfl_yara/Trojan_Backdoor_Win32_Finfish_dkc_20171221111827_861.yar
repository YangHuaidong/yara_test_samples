rule Trojan_Backdoor_Win32_Finfish_dkc_20171221111827_861 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Finfish.dkc"
		threattype = "BackDoor"
		family = "Finfish"
		hacker = "None"
		refer = "A7B990D5F57B244DD17E9A937A41E7F5"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-10-10"
	strings:
		$s0 = "rFsDd" nocase wide ascii
		$s1 = "xMyKuP?" nocase wide ascii
		$s2 = "tfudu" nocase wide ascii
		$s3 = "zc%C1" nocase wide ascii

	condition:
		all of them
}
