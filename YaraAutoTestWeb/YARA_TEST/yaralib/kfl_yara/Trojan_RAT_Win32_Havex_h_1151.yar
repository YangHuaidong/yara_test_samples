rule Trojan_RAT_Win32_Havex_h_1151
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Havex.h"
		threattype = "ICS,RAT"
		family = "Havex"
		hacker = "None"
		refer = "d1e202443dc0c1f0203f3da01a5d4235"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-04-24"
		description = "Detects the Havex RAT malware"
	strings:
		$s0 = {41 9C 74 00 75 00 69 00 64 00 64 00 6F 00 73 00 65 00 68 00 79 00 6F 00 68 00 69 00 72 00 67 00 61 00 65 00 6C 00 6F 00 6E}
	    $s1 = {41 9C 67 00 79 00 74 00 6F 00 77 00 6F 00 79 00 76 00 74 00 6F 00 73}
		$s2 = "IsDebuggerPresent"
		$s3 = "DeleteCriticalSection"
		$s4 = {61 00 63 00 65 00 61 00 73 00 6F 00 77 00 65 00 71 00 65 00 74 00 61 00 76 00 65 00 74 00 69 00 62 00 73 00 75 00 69 00 67}
		$5 = {6E 00 66 00 65 00 6F 00 6E 00 68 00 65 00 67 00 69 00 65 00 72 00 65 00 64 00 72 00 6F 00 6F 00 64 00 68 00 6F 00 6D}
	condition:
	    all of them
}