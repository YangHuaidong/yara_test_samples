rule Trojan_DDoS_Linux_Mirai_2A_1100
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Mirai.2A"
		threattype = "DDoS"
		family = "Mirai"
		hacker = "None"
		refer = "b1bb204cf2bf849c6c1139068f33ecf2"
		author = "Luoxuan"
		comment = "None"
		date = "2019-04-24"
		description = "None"
	strings:
		$s0 = {59 53 59 5e 4f 47} // system
		$s1 = {5d 4b 5e 49 42 4e 45 4d}//watchdog
		$s2 = {59 42 4f 46 46} // shell
		$s3 = {05 48 43 44 05 48 5f 59 53 48 45 52} // /bin/busybox
	condition:
		all of them
}