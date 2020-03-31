rule Trojan_DDoS_Linux_Gafgyt_Bj_760
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.Bj"
		threattype = "DDoS"
		family = "Gafgyt"
		hacker = "None"
		refer = "488B5F612F70731566F2C7C66E7FC00E"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2017-09-21"
		description = "None"
	strings:
		$s0 = "/bin/busybox"
		$s1 = "/bin/sh"
		$s2 = "REPORT %s:%s:%s"
		$s3 = "BusyBox"
		$s4 = "crti.S"
		$s5 = "crtn.S"
	condition:
		all of them
		//(1 or ($s0 and $s1)) and $s2 and $s3 and $s4 and $s5 and $s6 and $s7
}