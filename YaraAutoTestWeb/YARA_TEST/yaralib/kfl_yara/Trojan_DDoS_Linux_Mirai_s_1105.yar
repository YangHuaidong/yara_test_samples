rule Trojan_DDoS_Linux_Mirai_s_1105
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Mirai.s"
		threattype = "DDoS"
		family = "Mirai"
		hacker = "None"
		refer = "dc3ae184620eb689787c3aee42ff15dd"
		author = "Luoxuan"
		comment = "None"
		date = "2019-05-06"
		description = "None"
	strings:
		$s0 = "system"
		$s1 = "watchdog"
		$s2 = "shell"
		$s3 = "/bin/busybox"
		$s4 = "nameserver"
	condition:
		all of them
}