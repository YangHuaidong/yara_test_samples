rule Trojan_Backdoor_Win32_Duqu2_c_1144
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Duqu2.c"
		threattype = "ICS,Backdoor"
		family = "Duqu2"
		hacker = "None"
		refer = "9749d38ae9b9ddd81b50aad679ee87ec"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-04-28"
		description = "None"
    strings:
		$s0 = {50 49 44 3A 20 25 75}
		$s1 = {55 73 69 6E 67 20 25 53}
		$s2 = {73 00 76 00 63 00 68 00 6F 00 73 00 74 00 2E 00 65 00 78 00 65}
		$s3 = {52 65 61 64 50 72 6F 63 65 73 73 4D 65 6D 6F 72 79}
		$s4 = {43 72 65 61 74 65 4D 75 74 65 78 57}
    condition:
		all of them
}