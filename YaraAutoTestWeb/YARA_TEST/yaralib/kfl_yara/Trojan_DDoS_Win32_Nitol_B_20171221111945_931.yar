rule Trojan_DDoS_Win32_Nitol_B_20171221111945_931 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Nitol.B"
		threattype = "DDOS"
		family = "Nitol"
		hacker = "None"
		refer = "13c32f2bc2aa3abfc7749e215fc04ab1"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-09-06"
	strings:
		$s0 = "g1fd.exe"
		$s1 = "%s %d:%d %s"
		$s3 = "caonima"
		$s4 = "asdfgh"
		$s5 = "%u Gbps"
		$s6 = "NewArean.exe"
		$s7 = "hra%u.dll"
		$s8 = "lpk.attack"

	condition:
		all of them
}
