rule Trojan_DDoS_Linux_Xaynnalc_A_20170511162006_997_289 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Xaynnalc.A"
		threattype = "DDOS"
		family = "Xaynnalc"
		hacker = "None"
		refer = "1cd1058b8516efd6b075631cc380c59f"
		description = "None"
		comment = "None"
		author = "cjf"
		date = "2017-05-02"
	strings:
		$s0 = "COLLECTION /wallace DAYDREAM/1.1" nocase
		$s1 = "Starting"
		$s2 = "ddos..."
		$s3 = "DayDream" nocase
		$s4 = "HTTP" fullword

	condition:
		all of them
}
