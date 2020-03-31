rule Trojan_DDoS_Linux_Gafgyt_Ad_1046
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.Ad"
		threattype = "DDoS"
		family = "Gafgyt"
		hacker = "None"
		refer = "c16572d49b62d0d11adb1b19df7258d7"
		author = "lizhenling"
		comment = "None"
		date = "2019-02-20"
		description = "None"

	strings:		
		$s0 = "recvLine"
		$s1 = "macAddress"
		$s2 = "listFork"
		$s3 = "/usr/sbin/telnetd"
		$s4 = "makeIPPacket"
		$s5 = "fdgets"
		$s6 = "processCmd"
		
	condition:
		5 of them
}