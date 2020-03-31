rule Trojan_DDoS_Linux_Mirai_Huawei_1104
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Mirai.Huawei"
		threattype = "DDoS"
		family = "Mirai"
		hacker = "None"
		refer = "4a63ead49076c3d480f548579bff9b4e"
		author = "Luoxuan"
		comment = "None"
		date = "2019-05-06"
		description = "None"
	strings:
		$s0 = "watchdog"
		$s1 = "HuaweiHomeGateway"
		$s2 = "/bin/busybox"
	condition:
		all of them
}