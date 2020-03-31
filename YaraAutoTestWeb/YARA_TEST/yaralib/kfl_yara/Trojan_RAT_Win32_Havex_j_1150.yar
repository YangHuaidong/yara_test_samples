rule Trojan_RAT_Win32_Havex_j_1150
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Havex.j"
		threattype = "ICS,RAT"
		family = "Havex"
		hacker = "None"
		refer = "f1d9f43908b8561bea57bd7a573dfef6"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-04-25"
		description = "Detects the Havex RAT malware"
	strings:
	    $s0 = {63 6F 6D 6D 61 6E 64}
		$s1 = {4A 00 61 00 76 00 61 00 20 00 55 00 70 00 64 00 61 00 74 00 65 00 72 00 2E 00 65 00 78 00 65}
		$s2 = {31 00 2E 00 70 00 6E 00 67}
		$s3 = {63 00 6D 00 64 00 2E 00 65 00 78 00 65}
		$s4 = {53 00 74 00 61 00 72 00 74 00 65 00 64}
	condition:
	    all of them
}