rule Trojan_Backdoor_Win32_Tzeebot_e_1138
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Tzeebot.e"
		threattype = "ICS,Backdoor"
		family = "Tzeebot"
		hacker = "None"
		refer = "0b80a8d2c56789b4bda9a56a53e7e2b1"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-04-28"
		description = "None"
    strings:
		$s0 = {4D 00 63 00 73 00 68 00 69 00 65 00 6C 00 64 00 2E 00 65 00 78 00 65}
		$s1 = {53 00 63 00 61 00 6E 00 33 00 32 00 2E 00 65 00 78 00 65}
		$s2 = {63 00 63 00 53 00 76 00 63 00 48 00 73 00 74 00 2E 00 65 00 78 00 65}
		$s3 = {74 00 61 00 73 00 6B 00 6C 00 69 00 73 00 74}
		$s4 = {66 00 69 00 72 00 65 00 77 00 61 00 6C 00 6C}
		$s5 = {47 00 65 00 74 00 20 00 41 00 6E 00 74 00 69 00 53 00 70 00 79 00 77 00 61 00 72 00 65 00 20 00 42 00 79 00 20 00 57 00 4D 00 49 00 43 00 3A}
		$s6 = {53 00 63 00 61 00 6E 00 6E 00 69 00 67 00 3A 00 20 00 52 00 75 00 6E 00 6E 00 69 00 6E 00 67 00 28 00 61 00 63 00 74 00 69 00 76 00 65 00 29}
    condition:
		all of them
}