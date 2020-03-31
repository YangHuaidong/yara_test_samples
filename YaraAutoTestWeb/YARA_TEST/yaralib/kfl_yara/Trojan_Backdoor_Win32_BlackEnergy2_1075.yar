rule Trojan_Backdoor_Win32_BlackEnergy2_1075
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.BlackEnergy2"
		threattype = "ICS,Backdoor"
		family = "BlackEnergy2"
		hacker = "None"
		refer = "4d5c00bddc8ea6bfa9604b078d686d45"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-03-09"
		description = "None"
	strings:
		$s0 = {68 97 04 81 1D 6A 01}
		$s1 = {68 A8 06 B0 3B 6A 02}
		$s2 = {68 14 06 F5 33 6A 01}
		$s3 = {68 AF 02 91 AB 6A 01}
		$s4 = {68 8A 86 39 56 6A 02}
		$s5 = {68 19 2B 90 95 6A 01}
		$s6 = {(68 | B?) 11 05 90 23}
		$s7 = {(68 | B?) EB 05 4A 2F}
		$s8 = {(68 | B?) B7 05 57 2A}
	condition:
		4 of them
}