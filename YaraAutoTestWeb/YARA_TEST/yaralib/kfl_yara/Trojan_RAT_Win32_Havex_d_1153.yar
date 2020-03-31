rule Trojan_RAT_Win32_Havex_d_1153
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Havex.d"
		threattype = "ICS,RAT"
		family = "Havex"
		hacker = "None"
		refer = "0a588d44cc1507be70fd520f0314c416"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-04-22"
		description = "Detects the Havex RAT malware"
	strings:
		$s0 = {43 00 6C 00 6F 00 75 00 64 00 77 00 6B 00 73 00 49 00 6E 00 73 00 74 00 61 00 6C 00 6C 00 2E 00 65 00 78 00 65} //CloudwksInstall.exe
	    $s1 = {33 00 36 00 30 00 73 00 64 00 62 00 2E 00 65 00 78 00 65}
		$s2 = {63 00 61 00 6C 00 63 00 2E 00 65 00 78 00 65}
		$s3 = {63 00 6D 00 64 00 2E 00 65 00 78 00 65}
		$s4 = {44 3A 5C 58 69 61 5A 61 69 51 69 5C 50 72 6F 6A 65 63 74 43 6F 70 79 5C 4D 69 78 65 64 5C 70 64 62 6D 61 70 5C 57 61 6E 4E 65 6E 67 5C 49 6E 73 74 61 6C 6C 2E 70 64 62}
		$s5 = {25 00 73 00 79 00 73 00 74 00 65 00 6D 00 72 00 6F 00 6F 00 74 00 25 00 5C}
	condition:
	    all of them
}