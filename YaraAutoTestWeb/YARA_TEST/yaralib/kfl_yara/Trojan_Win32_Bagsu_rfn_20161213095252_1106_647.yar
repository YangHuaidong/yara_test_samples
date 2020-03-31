rule Trojan_Win32_Bagsu_rfn_20161213095252_1106_647 
{
	meta:
		judge = "black"
		threatname = "Trojan/Win32.Bagsu.rfn"
		threattype = "DDOS"
		family = "Bagsu"
		hacker = "None"
		refer = "31B1595247F608D092CCDA5A018DDD76,03434E8B43AA43DF2AFC9258B7C281EC"
		description = "None"
		comment = "None"
		author = "april_xu"
		date = "2016-05-09"
	strings:
		$s0 = "SSynFloodThread"fullword nocase wide ascii
		$s1 = "Address %d : %s"fullword nocase wide ascii
		$s2 = "Bad host lookup."fullword nocase wide ascii
		$s3 = "Host name is: %s"fullword nocase wide ascii
		$s4 = "Error %d when getting local host name.n"fullword nocase wide ascii
		$s5 = "SynFloodThread1"fullword nocase wide ascii
		$s6 = "SynBigFloodThread1"fullword nocase wide ascii
		$s7 = "setsockopt Error"fullword nocase wide ascii

	condition:
		4 of them
}
