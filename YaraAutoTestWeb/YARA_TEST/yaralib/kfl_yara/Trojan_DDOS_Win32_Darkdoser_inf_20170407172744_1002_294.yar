rule Trojan_DDOS_Win32_Darkdoser_inf_20170407172744_1002_294 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDOS]/Win32.Darkddoser.inf"
		threattype = "DDOS"
		family = "Darkddoser"
		hacker = "None"
		refer = "9071a908ceccaf4ea08924e0695033d0"
		description = "None"
		comment = "None"
		author = "None"
		date = "2017-03-20"
	strings:
		$s0 = "SYNStart" nocase
		$s1 = "UDPStart" nocase
		$s2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
		$s3 = "helloddoser" nocase
		$s4 = "autorun.inf" nocase

	condition:
		4 of them
}
