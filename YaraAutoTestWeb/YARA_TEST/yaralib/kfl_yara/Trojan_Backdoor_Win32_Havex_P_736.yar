rule Trojan_Win32_Havex_P_736
{
	meta:
		judge = "black"
		threatname = "Trojan[BackDoor]/Win32.Havex.P"
		threattype = "BackDoor"
		family = "Havex"
		hacker = "None"
		refer = "780b373d6a36de674aa4c7a262e2124f"
		author = "HuangYY"
		comment = "None"
		date = "2017-09-08"
		description = "None"

	strings:		
		$s0 = "bzip2/libbzip2"
		$s1 = "jseward@bzip.org"
		$s3 = "havex"
		$s4 = {73 00 74 00 61 00 6C 00 70 00 72 00 6F 00 66 00 2E 00 63 00 6F 00 6D 00 2E 00 75 00 61}
		$s5 = {77 00 77 00 77 00 2E 00 63 00 6F 00 6D 00 65 00 74 00 6F 00 74 00 68 00 65 00 74 00 72 00 75 00 74 00 68 00 2E 00 63 00 6F 00 6D}
	condition:
		all of them
}