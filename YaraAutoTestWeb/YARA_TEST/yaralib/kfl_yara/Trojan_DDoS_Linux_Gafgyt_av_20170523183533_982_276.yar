rule Trojan_DDoS_Linux_Gafgyt_av_20170523183533_982_276 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.av"
		threattype = "DDOS"
		family = "Gafgyt"
		hacker = "None"
		refer = "4e07aee64538b58d4939d6d2b7a68930"
		description = "None"
		comment = "None"
		author = "cjf"
		date = "2017-05-09"
	strings:
		$s0 = "telnet"
		$s1 = "!root"
		$s2 = "zyad1234"
		$s3 = "guest12345"
		$s4 = "PING"
		$s5 = ":>%$#"
		$s6 = "START"
		$s7 = "Shit Failed"

	condition:
		all of them
}
