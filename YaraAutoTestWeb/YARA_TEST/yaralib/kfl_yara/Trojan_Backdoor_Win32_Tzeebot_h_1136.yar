rule Trojan_Backdoor_Win32_Tzeebot_h_1136
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Tzeebot.h"
		threattype = "ICS,Backdoor"
		family = "Tzeebot"
		hacker = "None"
		refer = "eac61634da4513a10b596e6c8c299126"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-04-28"
		description = "None"
    strings:
		$s0 = {25 30 32 64 2F 25 30 32 64 2F 25 30 34 64 2C 20 25 30 32 64 3A 25 30 32 64 3A 25 30 32 64}
		$s1 = {66 3A 5C 64 64 5C 76 63 74 6F 6F 6C 73 5C 63 72 74 5F 62 6C 64 5C 73 65 6C 66 5F 78 38 36 5C 63 72 74 5C 73 72 63 5C}
		$s2 = {50 72 6F 67 72 61 6D 3A 20 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73}
    condition:
		all of them
}