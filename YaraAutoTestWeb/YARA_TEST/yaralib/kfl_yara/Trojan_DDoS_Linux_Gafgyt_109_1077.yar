rule Trojan_DDoS_Linux_Gafgyt_109_1077
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt"
		threattype = "DDoS"
		family = "Gafgyt"
		hacker = "None"
		refer = "9d672d2164dcfeb0c68c8e293ad941d2"
		author = "lizhenling"
		comment = "None"
		date = "2019-03-21"
		description = "None"

	strings:		
		$s0 = "currentServer"
		$s1 = "makeIPPacket"
		$s2 = "ourIP"
		$s3 = "listFork"
		$s4 = "mainCommSock"
		$s5 = "read_with_timeout"
		$s6 = "processCmd"

	condition:
		6 of them
}