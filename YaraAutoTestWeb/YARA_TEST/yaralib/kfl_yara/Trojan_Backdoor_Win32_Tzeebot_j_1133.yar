rule Trojan_Backdoor_Win32_Tzeebot_j_1133
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Tzeebot.j"
		threattype = "ICS,Backdoor"
		family = "Tzeebot"
		hacker = "None"
		refer = "985e86ac1854585d2771fd173b63b98b"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-04-29"
		description = "None"
    strings:
		$s0 = {41 00 64 00 62 00 52 00 65 00 70 00 6F 00 53 00 76 00 63 00 2E 00 65 00 78 00 65}
		$s1 = {72 00 65 00 70 00 6F 00 72 00 74 00 73 00 76 00 63 00 2E 00 65 00 78 00 65}
		$s2 = {5B 00 25 00 73 00 2E 00 25 00 38 00 78 00 25 00 30 00 38 00 78 00 5D}
		$s3 = {5C 72 65 70 6F 72 74 2E 74 78 74 00 5C 63 6F 6E 66 69 67 2E 62 69 6E}
    condition:
		all of them
}