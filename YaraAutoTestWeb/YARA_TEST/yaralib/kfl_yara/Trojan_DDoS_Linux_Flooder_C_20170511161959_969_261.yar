rule Trojan_DDoS_Linux_Flooder_C_20170511161959_969_261 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Flooder.C"
		threattype = "DDOS"
		family = "Flooder"
		hacker = "None"
		refer = "cf319d455821c5ed56a5c426ede0ac3d"
		description = "None"
		comment = "None"
		author = "cjf"
		date = "2017-05-02"
	strings:
		$s0 = "Good luck, Ebola-chan!" nocase
		$s1 = "Starting"
		$s2 = "Flood..."
		$s3 = "joomla"

	condition:
		all of them
}
