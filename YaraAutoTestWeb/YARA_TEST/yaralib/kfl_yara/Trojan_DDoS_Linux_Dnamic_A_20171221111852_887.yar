rule Trojan_DDoS_Linux_Dnamic_A_20171221111852_887 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Dnamic.A"
		threattype = "DDOS"
		family = "Dnamic"
		hacker = "None"
		refer = "a017d35ee1a637029de3a7c1ee120de9"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-02-15"
	strings:
		$s0 = "attack_tcp"
		$s1 = "Getcpuinfo"
		$s2 = "Calcpuuser"
		$s3 = "SendCpuMsg"
		$s4 = "checksum_ip"
		$s5 = "Getcpumhz"
		$s6 = "attack_udp"
		$s7 = "RecvDosMsg"
		$s8 = "attack_syn"
		$s9 = "checksum_tcpudp"

	condition:
		all of them
}
