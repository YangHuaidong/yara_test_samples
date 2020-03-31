rule Trojan_DDoS_Linux_Gafgyt_134_1078
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt"
		threattype = "DDoS"
		family = "Gafgyt"
		hacker = "None"
		refer = "de4186e903223d5c6c3d76d433f91397"
		author = "lizhenling"
		comment = "None"
		date = "2019-03-19"
		description = "None"

	strings:		
		$s0 = "readUntil"
		$s1 = "makeIPPacket"
		$s2 = "ourIP"
		$s3 = "vseflood"
		$s4 = "get_telnet_state_host"
		$s5 = "listFork"
		$s6 = "sendUDP"
		$s7 = "payloads"

	condition:
		all of them
}