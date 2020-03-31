rule Trojan_DDoS_Linux_Flooder_AW_20170913122055_893 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Flooder.AW"
		threattype = "DDOS"
		family = "Flooder"
		hacker = "None"
		refer = "350f3ab19135d3c2ab5ea2ddda41afb7"
		description = "None"
		comment = "None"
		author = "xc"
		date = "2017-08-31"
	strings:
		$s0 = "gethostbyname"
		$s1 = "/dev/urandom"
		$s2 = "bbbpgdhmrnrntttiareyyrcttast"
		$s3 = "attack_thread"
		$s4 = "AWAVAUATSH"
		$s5 = "class2ip6"
		$s6 = "-U UDP  attack"
		$s7 = "-T TCP  attack"
		$s8 = "-I ICMP attack"
		$s9 = "-B BMB  attack"

	condition:
		7 of them
}
