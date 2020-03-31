rule Trojan_DDoS_Win32_StormDDoS_scvost_20161213095157_1040_335 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.StormDDoS.scvost"
		threattype = "DDOS"
		family = "StormDDoS"
		hacker = "none"
		refer = "91ca928e82b68e2d5df53342ac91bcbd"
		description = "none"
		comment = "none"
		author = "Djw"
		date = "2016-11-29"
	strings:
		$s0 = "\\scvost.bat"
		$s1 = "\\%c%c%c%c%c.bat"
		$s2 = "%c%c%c%c%c.bat"
		$s3 = "Providesbia czlynb security."

	condition:
		3 of them
}
