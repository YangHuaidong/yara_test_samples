rule Trojan_DDoS_Linux_Mirai_F9_1095
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Mirai.F9"
		threattype = "DDoS"
		family = "Mirai"
		hacker = "None"
		refer = "930a9088d3657f73f3ea7bfd097a0116"
		author = "Luoxuan"
		comment = "None"
		date = "2019-04-17"
		description = "None"
	strings:
		$s0 = {8a 80 8a 8d 9c 94} // system
		$s1 = {8e 98 8d 9a 91 9d 96 9e}//watchdog
		$s2 = {8a 91 9c 95 95} // shell
		$s3 = {d6 9b 90 97 d6 9b 8c 8a 80 9b 96 81} // /bin/busybox
	condition:
		all of them
}