rule Trojan_DDoS_Linux_Mirai_0x10_1168
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Mirai.0x7C"
		threattype = "DDoS"
		family = "Mirai"
		hacker = "None"
		refer = "e64f262357ec9f1fa26caae7a96302cd"
		author = "Luoxuan"
		comment = "None"
		date = "2019-06-14"
		description = "None"
	strings:
		$s0 = "{3f 72 65 63 69 72 7f 68}" // /busybox
		$s1 = "{67 71 64 73 78 74 7f 77}" // watchdog
		$s2 = {63 78 75 7c 7c} // shell
	condition:
		all of them
}