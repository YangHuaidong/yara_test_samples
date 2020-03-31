rule Trojan_DDoS_Win32_Nitol_E_20171221111947_938 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Nitol.E"
		threattype = "DDOS"
		family = "Nitol"
		hacker = "None"
		refer = "617723f03f9f5b0d93f90abf09845542"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-08-18"
	strings:
		$s0 = "%c%c%c%c%ccn.exe"
		$s1 = "\\%s %d:%d %s"
		$s3 = "%04d%02d%02d"
		$s4 = "%u Gbps"
		$s5 = "%u Mbps"
		$s6 = "lpk.attack"
		$s7 = "g1fd.exe"

	condition:
		all of them
}
