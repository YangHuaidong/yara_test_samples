rule Trojan_DDoS_Linux_Gafgyt_ac_20170523183530_980_274 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.ac"
		threattype = "DDOS"
		family = "Gafgyt"
		hacker = "None"
		refer = "609a8c0edd2a019c1305232b16e7e0a0"
		description = "None"
		comment = "None"
		author = "cjf"
		date = "2017-05-08"
	strings:
		$s0 = "STOPATTK"
		$s1 = "PING"
		$s2 = "PONG"
		$s3 = "93.174.93.63:23"
		$s4 = "/dev/null"

	condition:
		all of them
}
