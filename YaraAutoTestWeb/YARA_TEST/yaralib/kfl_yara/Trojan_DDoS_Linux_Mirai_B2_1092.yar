rule Trojan_DDoS_Linux_Mirai_B2_1092
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Mirai.B2"
		threattype = "DDoS"
		family = "Mirai"
		hacker = "None"
		refer = "db291baebf60b92cb400608a117e7753"
		author = "Luoxuan"
		comment = "None"
		date = "2019-04-10"
		description = "None"
	strings:
		$s0 = {62 2f 24 23 62 2f 38 3e 34 2f 22 35} //  /bin/busybox
		$s1 = "/bin/busybox"
		$s2 = {3d 3f 22 2e 62 3e 28 21 2b 62 28 35 28} ///pro/self/exe
		$s3 = {23 2c 20 28 3e 28 3f 3b 28 3f} // nameserver
		$s4 = {62 29 28 3b 62 3a 2c 39 2e 25 29 22 2a} // dev/watchdog
		$s5 = {3e 25 28 21 21}//shell
	condition:
		all of them
}