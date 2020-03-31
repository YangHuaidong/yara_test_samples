rule Trojan_DDoS_Linux_Hajime_20170523183534_985_278 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Hajime"
		threattype = "DDOS"
		family = "Hajime"
		hacker = "None"
		refer = "94662c3619762016c9d86a9be63a0961"
		description = "None"
		comment = "None"
		author = "cjf"
		date = "2017-05-08"
	strings:
		$s0 = "srelay"
		$s1 = "relay="
		$s2 = ">>HTTP CONN %s:%s"
		$s3 = "Already run"
		$s4 = "syslog"
		$s5 = "any"
		$s6 = "parse port number"

	condition:
		all of them
}
