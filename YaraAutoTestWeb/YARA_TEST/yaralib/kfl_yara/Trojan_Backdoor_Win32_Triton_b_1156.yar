rule Trojan_Backdoor_Win32_Triton_b_1156
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Triton.b"
		threattype = "ICS,Backdoor"
		family = "Triton"
		hacker = "None"
		refer = "437f135ba179959a580412e564d3107f"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-04-22"
		description = "None"
	strings:
        $s0 = {7C 70 8B A6 4C 00 01 2C 7C 63 00 A6 60 63 00 30 7C 63 01 24 7C 00 04 AC 7C 70 13}
        $s1 = {7F C3 F3 78 4B FF FF 94 39 1B FF EC A3 DD}
		$s2 = {7C 63 00 A6 7C 83 18 38 7C 63 01}
	condition:
		all of them
}