rule Trojan_Backdoor_Win32_Tzeebot_c_1140
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Tzeebot.c"
		threattype = "ICS,Backdoor"
		family = "Tzeebot"
		hacker = "None"
		refer = "0593352cadb2789c19c2660e02b2648b"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-04-28"
		description = "None"
    strings:
		$s0 = {63 6D 64 5F 31 3D 63 6D 64 2E 65 78 65 20 2F 6B 20 22 7B 30 7D 5C 73 65 72 76 69 63 65 2E 62 61 74 22 2C 30 31 3A 30 30 2C 30 30 3A 30 30 2C 79 65 73}
		$s1 = {63 6D 64 5F 32 3D 74 61 73 6B 6B 69 6C 6C 2E 65 78 65 20 2F 46 20 2F 49 4D 20 6E 65 6C 73 63 70 2E 65 78 65 2C 30 32 3A 30 30 2C 30 30 3A 30 30 2C 6E 6F}
		$s2 = {65 63 68 6F 20 79 7C 22 7B 30 7D 5C 6E 65 6C 73 63 70 2E 65 78 65 22 20 31 39 32 2E 31 36 38 2E 31 31 31 2E 33 20 2D 50 20 38 30 20 2D 43 20 2D 52 20 31 32 37 2E 30 2E 30 2E 31 3A 31 32 33 34 35 3A 31 32 37 2E 30 2E 30 2E 31 3A 33 33 38 39 20 2D 6C 20 61 20 2D 70 77 20 61}
    condition:
		all of them
}