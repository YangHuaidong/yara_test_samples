rule Trojan_DDoS_Win32_StormDDoS_2017_20170523183547_1031_327 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.StormDDoS.2017"
		threattype = "DDOS"
		family = "StormDDoS"
		hacker = "None"
		refer = "84DA400FEB42516D2CE3ECADA4913F1B,A022DABB713F6D6130C192EAF6AAFDED"
		description = "None"
		comment = "None"
		author = "sxy"
		date = "2017-05-10"
	strings:
		$a0 = "STORMDDOS"
		$s0 = "%c%c%c%c%c.exe"
		$s1 = "iexplore.exe"
		$s2 = "2017"
		$s3 = "Nationalpxd"
		$s4 = "Nationaltcw"

	condition:
		$a0 and 2 of ($s*)
}
