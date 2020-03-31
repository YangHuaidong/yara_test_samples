rule Trojan_DDoS_Win32_Nitol_Ex_794
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Nitol.Ex"
		threattype = "DDoS"
		family = "Nitol"
		hacker = "None"
		refer = "857852ac0b113607390d53ed0a699a90"
		author = "HuangYY"
		comment = "None"
		date = "2017-09-01"
		description = "None"

	strings:		
		$s0 = "g1fd.exe"
		$s1 = {FF 8B 15 0C 60 40 00 85 D2 0F 84 F1 00 00 00 FF}
		$s2 = "%s %d:%d %s"
		$s3 = "caonima"
		$s4 = "asdfgh"
		$s5 = "%u Gbps"
		$s6 = "NewArean.exe"
		$s7 = "hra%u.dll"
		$s8 = {E2 FA ED 0E FF 15 10 60 40 00 5A C3 50 52 80 3D}
		$s9 = {47 08 85 C0 74 48 8B 5F 0C 8B 70 04 33 D2 55 68}
		$s10 = {47 08 85 C0 74 48 8B 5F 0C 8B 70 04 33 D2 55 68}
		$s11 = {50 E8 52 D9 FF FF E8 31 FD FF FF 80 7B 28 01 75}
		$s12 = {85 D2 74 24 8B 4A F8 41 7F 1A 50 52 8B 42 FC E8}
	condition:
		7 of them
}