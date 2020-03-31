rule Trojan_Backdoor_Win32_Tzeebot_f_1137
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Tzeebot.f"
		threattype = "ICS,Backdoor"
		family = "Tzeebot"
		hacker = "None"
		refer = "18942a44d2b5f2bbf54e2c18ac293915"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-04-28"
		description = "None"
    strings:
		$s0 = {73 00 76 00 63 00 68 00 6F 00 73 00 74 00 2E 00 65 00 78 00 65}
		$s1 = "TmV0d29yayBldmVudA=="
		$s2 = "HookAllKeys"
		$s3 = "base64Binary"
		$s4 = "d2FpdGZvciBoZWhlIC90IDMNCg=="
		$s5 = "YjkzYy00OWExLSoudG11"
		$s6 = "U3lzdGVtTG9nXA=="
    condition:
		all of them
}