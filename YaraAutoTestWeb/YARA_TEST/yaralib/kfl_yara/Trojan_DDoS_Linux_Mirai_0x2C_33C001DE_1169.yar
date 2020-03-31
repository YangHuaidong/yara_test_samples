rule Trojan_DDoS_Linux_Mirai_0x2C_33C001DE_1169
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Mirai.0x2C_33C001DE"
		threattype = "DDoS"
		family = "Mirai"
		hacker = "None"
		refer = "ea626a8300f4b00684a897d3016d44ff"
		author = "Luoxuan"
		comment = "None"
		date = "2019-06-19"
		description = "None"
	strings:
		$s0 = {03 4e 59 5f 55 4e 43 54} // /busybox
		$s1 = {5b 4d 58 4f 44 48 43 4b} // watchdog
		$s2 = {5f 44 49 40 40} // shell
	condition:
		all of them
}