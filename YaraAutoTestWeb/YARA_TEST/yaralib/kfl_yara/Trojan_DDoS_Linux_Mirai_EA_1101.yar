rule Trojan_DDoS_Linux_Mirai_EA_1101
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Mirai.EA"
		threattype = "DDoS"
		family = "Mirai"
		hacker = "None"
		refer = "6dee8cd58fc4570c52938e3afd1da58b"
		author = "Luoxuan"
		comment = "None"
		date = "2019-04-24"
		description = "None"
	strings:
		$s0 = {86 85 9c 8f ca 93 85 9f} // love you 
		$s1 = {9d 8b 9e 89 82 8e 85 8d}//watchdog
		$s2 = {99 82 8f 86 86} // shell
		$s3 = {c5 88 83 84 c5 88 9f 99 93 88 85 92} // /bin/busybox
		$s4 = {99 93 99 9e 8f 87} // system
	condition:
		all of them
}