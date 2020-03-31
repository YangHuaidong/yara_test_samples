rule Trojan_Backdoor_Win32_Tzeebot_d_1139
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Tzeebot.d"
		threattype = "ICS,Backdoor"
		family = "Tzeebot"
		hacker = "None"
		refer = "08eabb6164b1b12307931e4f2d95f7c6"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-04-28"
		description = "None"
    strings:
		$s0 = {7A 68 43 61 74 20 2D 6C 20 2D 70 20 31 32 33 34 20 2D 65 20 43 3A 5C 57 69 6E 64 6F 77 73 5C 53 79 73 74 65 6D 33 32 5C 63 6D 64 2E 65 78 65 20 20 20 3A 3A 20 53 65 72 76 65 72 0A}
		$s1 = {7A 68 43 61 74 20 5B 2D 6C 5D 20 5B 2D 68 5D 20 5B 2D 78 5D 20 5B 2D 69 20 3C 49 50 3E 5D 20 2D 70 20 3C 50 6F 72 74 3E 20 5B 2D 74 69 20 3C 54 75 6E 6E 65 6C 20 49 50 3E 5D 20 2D 74 70 20 3C 54 75 6E 6E 65 6C 20 50 6F 72 74 3E}
		$s2 = {4E 4F 54 45 3A 20 69 66 20 79 6F 75 20 64 6F 6E 27 74 20 75 73 65 20 2D 78 20 6F 72 20 2D 68 20 6F 70 74 69 6F 6E 2C 20 69 74 20 63 61 6E 20 77 6F 72 6B 20 77 69 74 68 20 6E 63 2E 65 78 65 0A}
    condition:
		all of them
}