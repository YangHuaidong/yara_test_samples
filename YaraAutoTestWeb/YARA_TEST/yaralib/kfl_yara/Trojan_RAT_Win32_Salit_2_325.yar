rule Trojan_RAT_Win32_Sality_D_2_325
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Sality"
		threattype = "RAT"
		family = "Sality"
		hacker = "APT Dragonfly"
		killchain = "None"
		refer = "f878db63a23a534b1f066d61f80f65ce"
		author = "HYY"
		comment = "None"
		date = "2018-07-16"
		description = "None"
	strings:
		$s0 = {79 72 66 3C 5B 4C 6F 72 64 50 45 5D E0 00 0F 01 0B 01 06 00 00 02}
		$s1 = {48 00 65 00 6C 00 6C 00 6F 00 20 00 77 00 6F 00 72 00 6C 00 64 00 21}
		$s2 = {43 00 61 00 70 00 74 00 69 00 6F 00 6E 00}
		$s3 = {45 78 69 74 50 72 6F 63 65 73 73 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 C3 01 4D 65 73 73 61 67 65 42 6F 78 57 00 55 53 45 52 33 32 2E 64 6C 6C}
		
	condition:
		all of them
}