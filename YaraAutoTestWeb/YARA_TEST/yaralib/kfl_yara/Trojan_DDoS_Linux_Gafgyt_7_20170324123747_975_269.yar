rule Trojan_DDoS_Linux_Gafgyt_7_20170324123747_975_269 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.7"
		threattype = "DDOS"
		family = "Gafgyt"
		hacker = "None"
		refer = "04618c7a170179adcc09287fe402943d"
		description = "None"
		comment = "None"
		author = "cjf"
		date = "2017-03-14"
	strings:
		$s0 = "root"
		$s1 = "gayfgt"
		$s2 = "PONG!"
		$s3 = ":>%$#"

	condition:
		all of them
}
