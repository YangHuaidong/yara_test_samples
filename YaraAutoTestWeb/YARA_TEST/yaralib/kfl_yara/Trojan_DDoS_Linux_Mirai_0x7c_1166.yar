rule Trojan_DDoS_Linux_Mirai_0x7C_1166
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Mirai.0x7C"
		threattype = "DDoS"
		family = "Mirai"
		hacker = "None"
		refer = "EAC83ADE2BD5182CE0C5DD7B829E42C2"
		author = "Luoxuan"
		comment = "None"
		date = "2019-06-13"
		description = "None"
	strings:
		$s0 = {53 1e 15 12 53 1e 09 0f 05 1e 13 04} // /bin/busybox
		$s1 = {0b 1d 08 1f 14 18 13 1b} // watchdog
		$s2 = {0f 14 19 10 10} // shell
		$s3 = {12 1d 11 19 0f 19 0e 0a 19 0e} // nameserver
	condition:
		all of them
}