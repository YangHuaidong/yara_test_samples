rule Trojan_DDoS_Linux_Gafgyt_T_764
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.T"
		threattype = "DDoS"
		family = "Gafgyt"
		hacker = "None"
		refer = "2C12D90CE214364866305674E4FF4F87,EA5AFD43ADFA0AD01C759CAA115608BC"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2017-09-07"
		description = "None"
	strings:
		$s0 = "cd /tmp && wget"
		$s1 = "TELNETSCAN START | STOP"
		$s2 = "My IP: %s"
		$s3 = "BOGOMIPS"
		$s4 = "/proc/net/route"
	condition:
		all of them
}