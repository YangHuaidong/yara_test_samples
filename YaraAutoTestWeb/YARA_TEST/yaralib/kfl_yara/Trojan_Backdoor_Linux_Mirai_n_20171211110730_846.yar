rule Trojan_Backdoor_Linux_Mirai_n_20171211110730_846 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Mirai.n"
		threattype = "DDOS"
		family = "Mirai"
		hacker = "None"
		refer = "009c1ee3916d188d456239fe5458698e"
		description = "None"
		comment = "None"
		author = "mqx"
		date = "2017-11-23"
	strings:
		$s0 = "POST /cdn-cgi/"
		$s1 = "/dev/misc/watchdog"
		$s2 = "enter"
		$s3 = "assword"
		$s4 = "/proc/net/tcp"

	condition:
		all of them
}
