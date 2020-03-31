rule Trojan_Backdoor_Win32_Tzeebot_mail_1143
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Tzeebot.mail"
		threattype = "ICS,Backdoor"
		family = "Tzeebot"
		hacker = "None"
		refer = "0ad6a01a916f14fc24fa43e46813b3bb"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-04-28"
		description = "None"
    strings:
		$s0 = {6E 65 74 73 63 70 2E 65 78 65}
		$s1 = {57 00 53 00 63 00 72 00 69 00 70 00 74 00 2E 00 53 00 68 00 65 00 6C 00 6C}
		$s2 = {2F 53 00 65 00 6E 00 64 00 4D 00 61 00 69 00 6C 00 2E 00 2E 00 2E}
		$s3 = {19 65 00 6D 00 61 00 69 00 6C 00 41 00 64 00 64 00 72 00 65 00 73 00 73}
		$s4 = {54 00 69 00 6E 00 79 00 5A 00 42 00 6F 00 74 00 2E 00 50 00 72 00 6F 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2E 00 52 00 65 00 73 00 6F 00 75 00 72 00 63 00 65 00 73}
		$s5 = {6B 65 79 62 6F 61 72 64 48 6F 6F 6B 53 74 72 75 63 74}
		$s6 = {53 00 59 00 53 00 54 00 45 00 4D 00 5C 00 43 00 75 00 72 00 72 00 65 00 6E 00 74 00 43 00 6F 00 6E 00 74 00 72 00 6F 00 6C 00 53 00 65 00 74 00 5C 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5C 00 54 00 63 00 70 00 69 00 70 00 5C 00 50 00 61 00 72 00 61 00 6D 00 65 00 74 00 65 00 72 00 73}
    condition:
		all of them
}