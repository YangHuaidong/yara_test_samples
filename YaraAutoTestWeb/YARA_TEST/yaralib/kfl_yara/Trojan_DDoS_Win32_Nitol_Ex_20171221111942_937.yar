rule Trojan_DDoS_Win32_Nitol_Ex_20171221111942_937 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Nitol.Ex"
		threattype = "DDOS"
		family = "Nitol"
		hacker = "None"
		refer = "857852ac0b113607390d53ed0a699a90"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-09-01"
	strings:
		$s0 = "g1fd.exe"
		$s1 = { ff 8b 15 0c 60 40 00 85 d2 0f 84 f1 00 00 00 ff }
		$s2 = "%s %d:%d %s"
		$s3 = "caonima"
		$s4 = "asdfgh"
		$s5 = "%u Gbps"
		$s6 = "NewArean.exe"
		$s7 = "hra%u.dll"
		$s8 = { e2 fa ed 0e ff 15 10 60 40 00 5a c3 50 52 80 3d }
		$s9 = { 47 08 85 c0 74 48 8b 5f 0c 8b 70 04 33 d2 55 68 }
		$s10 = { 47 08 85 c0 74 48 8b 5f 0c 8b 70 04 33 d2 55 68 }
		$s11 = { 50 e8 52 d9 ff ff e8 31 fd ff ff 80 7b 28 01 75 }
		$s12 = { 85 d2 74 24 8b 4a f8 41 7f 1a 50 52 8b 42 fc e8 }

	condition:
		7 of them
}
