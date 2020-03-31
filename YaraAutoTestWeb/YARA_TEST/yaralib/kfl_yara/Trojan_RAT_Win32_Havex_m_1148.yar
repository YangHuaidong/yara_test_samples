rule Trojan_RAT_Win32_Havex_m_1148
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Havex.m"
		threattype = "ICS,RAT"
		family = "Havex"
		hacker = "None"
		refer = "67973a848f62078ec0d21b886f8ffff0"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-04-25"
		description = "Detects the Havex RAT malware"
	strings:
	    $s0 = {46 00 69 00 6C 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6F 00 6E}
		$s1 = {44 00 4C 00 51 00 2E 00 65 00 78 00 65}
		$s2 = {68 74 74 70 3A 2F 2F 6F 63 73 70 2E 76 65 72 69 73 69 67 6E 2E 63 6F 6D}
		$s3 = {3C 61 73 73 65 6D 62 6C 79 20 78 6D 6C 6E 73 3D 22 75 72 6E 3A 73 63 68 65 6D 61 73 2D 6D 69 63 72 6F 73 6F 66 74 2D 63 6F 6D 3A 61 73 6D 2E 76 31 22 20 6D 61 6E 69 66 65 73 74 56 65 72 73 69 6F 6E 3D 22 31 2E 30 22 3E}
	condition:
	    all of them
}