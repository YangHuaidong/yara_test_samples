rule Trojan_DDOS_Linux_MrBlack_J_20161213095141_993_285 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDOS]/Linux.MrBlack.J"
		threattype = "DDOS"
		family = "MrBlack"
		hacker = "QQ\\uff1a1150059519"
		refer = "1f2cf6ddba32bc62d01e67324e544b95,1fa17c6fc674ed682a3675e5dbecc82d,230F996F9E74FEAB4476EC7FC722C81C"
		description = "Linux MrBlack"
		comment = "None"
		author = "zhoufenyan"
		date = "2016-07-19"
	strings:
		$s0 = "DealwithDDoS"
		$s1 = "DDOS_BEGIN"
		$s2 = "DDOS_STOP"
		$s3 = "ServerConnectCli"
		$s4 = "BIG_Flood"
		$s5 = "UDP_Flood"
		$s6 = "SYN_Flood"

	condition:
		4 of them
}
