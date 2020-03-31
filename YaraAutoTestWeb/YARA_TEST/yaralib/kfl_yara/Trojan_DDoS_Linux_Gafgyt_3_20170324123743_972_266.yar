rule Trojan_DDoS_Linux_Gafgyt_3_20170324123743_972_266 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.3"
		threattype = "DDOS"
		family = "Gafgyt"
		hacker = "None"
		refer = "3355d3a01647b6267bed5c3d081dff55"
		description = "None"
		comment = "None"
		author = "cjf"
		date = "2017-03-14"
	strings:
		$s0 = ":>%$#"
		$s1 = "PONG!"
		$s2 = "My IP: %s"
		$s3 = "%s 2>&1"
		$s4 = "BUILD %s"
		$s5 = "SCANNER"

	condition:
		all of them
}
