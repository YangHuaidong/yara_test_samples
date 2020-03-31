rule Trojan_DDoS_Linux_Tsunami_20170523183541_996_288 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Tsunami"
		threattype = "DDOS"
		family = "Tsunami"
		hacker = "None"
		refer = "3c74ca2824424d616a7e3b2d290f2632"
		description = "None"
		comment = "None"
		author = "cjf"
		date = "2017-05-09"
	strings:
		$s0 = "+tcp"
		$s1 = "+udp"
		$s2 = "domain"
		$s3 = "ADMIN USER"
		$s4 = "Attacking"
		$s5 = "Fucking this nigger in the butt"
		$s6 = "MODE"

	condition:
		all of them
}
