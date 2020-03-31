rule Trojan_DDoS_Win32_Nitol_Ex_20170918171450_936 
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
		$s1 = "%s %d:%d %s"
		$s3 = "caonima"
		$s4 = "asdfgh"
		$s5 = "%u Gbps"
		$s6 = "NewArean.exe"
		$s7 = "hra%u.dll"

	condition:
		all of them
}
