rule Trojan_DDoS_Linux_Gafgyt_1_20170324123741_970_263 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.1"
		threattype = "DDOS"
		family = "Gafgyt"
		hacker = "None"
		refer = "16ee980d5961dcadda9b5a0fb1d67d4a"
		description = "None"
		comment = "None"
		author = "cjf"
		date = "2017-03-14"
	strings:
		$s0 = ":>%$#"
		$s1 = "Mozilla/5.0"
		$s2 = "PONG!"
		$s3 = "My IP: %s"
		$s4 = "jackmy*"

	condition:
		all of them
}
