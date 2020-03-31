rule Trojan_DDoS_Win32_Nitol_G_20171221111950_939 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Nitol.G"
		threattype = "DDOS"
		family = "Nitol"
		hacker = "None"
		refer = "c950019328af8756dcef0f687de232bf"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-09-01"
	strings:
		$s0 = "Explorer\\iexplore.exe"
		$s1 = "Yow! Bad host lookup."
		$s3 = "Windows Test My Test"
		$s4 = "Set IP_HDRINCL Error!"
		$s5 = "getting local host name.n"

	condition:
		all of them
}
