rule Trojan_DDoS_Linux_Mirai_0x38_1094
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Mirai.0x38"
		threattype = "DDoS"
		family = "Mirai"
		hacker = "None"
		refer = "0c74dad73a98f550301dab81c530683b,de6b656f286b88b017edbce393e3f268"
		author = "Luoxuan"
		comment = "None"
		date = "2019-04-16"
		description = "None"

	strings:
		$s0 = {4b 50 5d 54 54} //shell
		$s1 = {4f 59 4c 5b 50 5c 57 5f} //watchdog
		$s2 = {56 59 55 5d 4b 5d 4a 4e 5d 4a} //nameserver
		$s3 = {17 5a 51 56 17 5a 4d 4b 41 5a 57 40} ///bin/busybox
		
	condition:
		all of them
}