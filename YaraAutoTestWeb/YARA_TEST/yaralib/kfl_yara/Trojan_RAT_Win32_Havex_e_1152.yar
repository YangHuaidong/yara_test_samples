rule Trojan_RAT_Win32_Havex_e_1152
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Havex.e"
		threattype = "ICS,RAT"
		family = "Havex"
		hacker = "None"
		refer = "27fcad606b1d29369dcbb0b34175158d"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-04-22"
		description = "Detects the Havex RAT malware"
	strings:
		$s0 = {69 70 74 73 5C 69 70 74 73 2E 65 78 65}
	    $s1 = {69 70 74 73 5C 42 65 6E 69 20 4F 6B 75 2E 74 78 74}
	condition:
	    all of them
}