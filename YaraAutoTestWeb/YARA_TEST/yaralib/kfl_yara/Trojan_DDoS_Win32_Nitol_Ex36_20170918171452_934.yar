rule Trojan_DDoS_Win32_Nitol_Ex36_20170918171452_934 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Nitol.Ex36"
		threattype = "DDOS"
		family = "Nitol"
		hacker = "None"
		refer = "b90c4d8a911b4d564ad6b9ba568fba2c"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-09-01"
	strings:
		$s0 = "%u Mbps"
		$s1 = "Ling.pdb"
		$s3 = "/c del"
		$s4 = "%u Gbps"
		$s5 = "%c%c%c%c%ccn.exe"
		$s6 = "hra%u.dll"

	condition:
		all of them
}
