rule Trojan_DDoS_Linux_Gafgyt_4_20170324123744_973_267 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.4"
		threattype = "DDOS"
		family = "Gafgyt"
		hacker = "None"
		refer = "6dd4af11f55ed55901fc4e518427cc2d"
		description = "None"
		comment = "None"
		author = "cjf"
		date = "2017-03-14"
	strings:
		$s0 = ":>%$#"
		$s1 = "GET /fuck1hex"
		$s2 = "PONG!"
		$s3 = "My IP: %s"
		$s4 = "Flooding"
		$s5 = "FUCKOFFNIGGER"

	condition:
		all of them
}
