rule Trojan_DDoS_Linux_Jenki_A_20171221111918_907 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Jenki.A"
		threattype = "DDOS"
		family = "Jenki"
		hacker = "None"
		refer = "d18033d987bde84a77560aef18ec291f"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-07-30"
	strings:
		$s0 = "system bytes     = %10u"
		$s1 = "in use bytes     = %10u"
		$s3 = "hooks.c"
		$s4 = "attack_tcp_con"
		$s5 = "attack_udp_root"
		$s6 = "attack_udp_std"
		$s7 = "attack_tcp_syn"
		$s8 = "attack_http_get_flood"
		$s9 = "attack_http_get_flood"
		$s10 = "attack_http_post_flood"
		$s11 = "attack_http_get_spider"
		$s12 = "attack_http_post_slow"
		$s13 = "attack_udp_dns"

	condition:
		7 of them
}
