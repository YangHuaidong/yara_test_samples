rule Trojan_DDoS_Linux_Gafgyt_8_20170324123749_976_270 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.8"
		threattype = "DDOS"
		family = "Gafgyt"
		hacker = "None"
		refer = "019f7ee397c6b7e0580260c8188233c6"
		description = "None"
		comment = "None"
		author = "cjf"
		date = "2017-03-14"
	strings:
		$s0 = "HTTP"
		$s1 = "PONG"
		$s2 = "Mozilla/5.0"
		$s3 = ":>%$#"
		$s4 = "HBiug655"
		$s5 = "LIKUGilkut76945890"

	condition:
		all of them
}
