rule Trojan_RAT_Win32_Havex_k_1149
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Havex.k"
		threattype = "ICS,RAT"
		family = "Havex"
		hacker = "None"
		refer = "ca67843bd3081221d926a2183ed2b394"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-04-25"
		description = "Detects the Havex RAT malware"
	strings:
	    $s0 = {41 00 63 00 72 00 6F 00 52 00 64 00 33 00 32 00 2E 00 65 00 78 00 65}
		$s1 = {65 00 64 00 75 00 2E 00 63 00 6E}
		$s2 = {67 00 6F 00 76 00 2E 00 63 00 6E}
		$s3 = {6F 00 72 00 67 00 2E 00 63 00 6E}
		$s4 = {55 52 4C 44 6F 77 6E 6C 6F 61 64 54 6F 46 69 6C 65 41}
		$s5 = {66 3D 25 64 26 76 3D 25 64 26 63 3D 25 64 26 69 3D 25 73}
	condition:
	    all of them
}