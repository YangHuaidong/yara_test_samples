rule Trojan_Backdoor_Win32_Tzeebot_b_1142
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Tzeebot.b"
		threattype = "ICS,Backdoor"
		family = "Tzeebot"
		hacker = "None"
		refer = "04fdf5b757764af8bc7ef88e0f8fe8c1"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-04-28"
		description = "None"
    strings:
		$s0 = {64 00 65 00 6C 00 20 00 2F 00 51 00 20 00 22}
		$s1 = {6D 00 6F 00 76 00 65 00 20 00 2F 00 59 00 20 00 22}
		$s2 = {63 00 6F 00 6E 00 66 00 69 00 67 00 2E 00 63 00 66 00 67}
		$s3 = {5C 00 72 00 32 00 36 00 33 00 2E 00 62 00 61 00 74}
		$s4 = {2F 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 74 00 6F 00 70}
    condition:
		all of them
}