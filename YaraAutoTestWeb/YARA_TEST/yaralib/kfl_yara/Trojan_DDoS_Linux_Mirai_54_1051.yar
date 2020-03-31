rule Trojan_DDoS_Linux_Mirai_54_1051
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Mirai"
		threattype = "DDoS"
		family = "Mirai"
		hacker = "None"
		refer = "d6879050c120aa061f2eaf4ed88ad310"
		author = "lizhenling"
		comment = "None"
		date = "2019-02-26"
		description = "None"

	strings:		
		$s0 = "gLEKLG"
		$s1 = "xOStDMqkr"
		$s2 = "attack_get_opt_ip"
		$s3 = "killer_kill_by_port"
		$s4 = "attack_udp_plain"
		$s5 = "scanner_kill"
		$s6 = "LOCAL_ADDR"
		
	condition:
		all of them
}