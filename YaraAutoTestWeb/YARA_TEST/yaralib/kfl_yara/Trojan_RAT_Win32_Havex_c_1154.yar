rule Trojan_RAT_Win32_Havex_c_1154
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Havex.c"
		threattype = "ICS,RAT"
		family = "Havex"
		hacker = "None"
		refer = "09eaeb550f706fe51da4021c43125070"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-04-22"
		description = "Detects the Havex RAT malware"
	strings:
		$s0 = {43 3A 5C 55 73 65 72 73 5C 77 6F 77 2D 67 5C 44 6F 63 75 6D 65 6E 74 73 5C 56 69 73 75 61 6C 20 53 74 75 64 69 6F 20 32 30 31 30 5C 50 72 6F 6A 65 63 74 73 5C 4A 61 76 61 55 70 64 61 74 65 72 5C 4A 61 76 61 55 70 64 61 74 65 72 5C 6F 62 6A 5C 78 38 36 5C 44 65 62 75 67 5C 4A 61 76 61 55 70 64 61 74 65 72 2E 70 64 62}
	    $s1 = "JavaUpdater.Properties"
		$s2 = "HttpWebResponse"
		$s3 = "WebResponse"
		$s4 = "System.Runtime.InteropServices"
		$s5 = "set_UserAgent"
	condition:
	    all of them
}