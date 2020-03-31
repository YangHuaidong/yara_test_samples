rule Trojan_Backdoor_Win32_Duqu2_a_1146
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Duqu2.a"
		threattype = "ICS,Backdoor"
		family = "Duqu2"
		hacker = "None"
		refer = "4541e850a228eb69fd0f0e924624b245"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-04-28"
		description = "None"
    strings:
		$s0 = {6E 74 6F 73 6B 72 6E 6C 2E 65 78 65 00 CC CC CC 6E 74 6B 72 6E 6C 70 61 2E 65 78 65}
		$s1 = {49 6F 44 65 6C 65 74 65 53 79 6D 62 6F 6C 69 63 4C 69 6E 6B}
		$s2 = {49 6F 44 65 6C 65 74 65 44 65 76 69 63 65}
		$s3 = {5C 00 44 00 65 00 76 00 69 00 63 00 65 00 5C 00 47 00 70 00 64 00 31 00 00 00 CC CC CC CC CC CC 5C 00 44 00 65 00 76 00 69 00 63 00 65 00 5C 00 47 00 70 00 64 00 30 00 00 00 CC CC CC CC CC CC 5C 00 44 00 6F 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5C 00 47 00 70 00 64 00 44 00 65 00 76}
    condition:
		all of them
}