rule Trojan_Backdoor_Win32_Tzeebot_a_1141
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Tzeebot.a"
		threattype = "ICS,Backdoor"
		family = "Tzeebot"
		hacker = "None"
		refer = "0512c5a8807e4fdeb662e61d81cd1645"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-04-28"
		description = "None"
    strings:
		$s0 = {63 00 6D 00 64 00 2E 00 65 00 78 00 65}
		$s1 = {5C 00 6D 00 69 00 6D 00 69 00 6B 00 61 00 74 00 7A 00 2E 00 65 00 78 00 65}
		$s2 = {6C 73 61 73 73 2E 65 78 65}
		$s3 = {6D 69 6E 69 64 75 6D 70 66 69 6C 65 2E 64 6D 70}
		$s4 = {52 65 6D 6F 74 65 20 63 6F 6D 6D 61 6E 64 20 25 73}
		$s5 = {52 65 61 64 50 72 6F 63 65 73 73 4D 65 6D 6F 72 79}
    condition:
		all of them
}