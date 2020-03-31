rule Trojan_Backdoor_Win32_Tzeebot_g_1135
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Tzeebot.g"
		threattype = "ICS,Backdoor"
		family = "Tzeebot"
		hacker = "None"
		refer = "f1301bad6da06f436e3a3de0244848e1"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-04-28"
		description = "None"
    strings:
		$s0 = "csext.exe"
		$s1 = {70 00 72 00 6F 00 67 00 72 00 61 00 6D 00 2C 00 7B 00 30 00 7D 00 5C 00 7B 00 7A 00 68 00 6E 00 61 00 6D 00 65 00 7D 00 24 00 24 00 20 00 2D 00 68 00 20 00 2D 00 78 00 20 00 2D 00 69 00 20 00 7B 00 64 00 6F 00 6D 00 61 00 69 00 6E 00 31 00 7D 00 20 00 2D 00 70 00 20 00 34 00 34 00 33 00 20 00 2D 00 65 00 20 00 63 00 3A 00 5C 00 77 00 69 00 6E 00 64 00 6F 00 77 00 73 00 5C 00 73 00 79 00 73 00 74 00 65 00 6D 00 33 00 32 00 5C 00 63 00 6D 00 64 00 2E 00 65 00 78 00 65 00 20 00 2C 00 74 00 61 00 73 00 6B 00 6B 00 69 00 6C 00 6C 00 2E 00 65 00 78 00 65 00 24 00 24 00 2F 00 46 00 20 00 2F 00 50 00 49 00 44 00 20 00 7B 00 70 00 69 00 64 00 7D}
		$s2 = {43 00 72 00 65 00 61 00 74 00 65 00 45 00 6E 00 63 00 72 00 79 00 70 00 74 00 6F 00 72 00 00 1F 43 00 72 00 65 00 61 00 74 00 65 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 6F 00 72}
		$s3 = "Remove"
    condition:
		all of them
}