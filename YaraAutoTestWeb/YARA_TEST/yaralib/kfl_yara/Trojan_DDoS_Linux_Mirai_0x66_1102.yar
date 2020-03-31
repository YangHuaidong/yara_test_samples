rule Trojan_DDoS_Linux_Mirai_0X66_1102
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Mirai.0X66"
		threattype = "DDoS"
		family = "Mirai"
		hacker = "None"
		refer = "c7fe52ce44715d6281e43509acb60d09"
		author = "Luoxuan"
		comment = "None"
		date = "2019-05-06"
		description = "None"
	strings:
		$s0 = {15 1f 15 12 03 0b} // system
		$s1 = {11 07 12 05 0e 02 09 01}//watchdog
		$s2 = {15 0e 03 0a 0a} // shell
		$s3 = {49 04 0f 08 49 04 13 15 1f 04 09 1e} // /bin/busybox
	condition:
		all of them
}