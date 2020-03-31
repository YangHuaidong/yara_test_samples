rule Trojan_DDoS_Linux_Mirai_2C_1103
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Mirai.2C"
		threattype = "DDoS"
		family = "Mirai"
		hacker = "None"
		refer = "2f6c257e400d9e9d3c05db63d767c92c"
		author = "Luoxuan"
		comment = "None"
		date = "2019-05-06"
		description = "None"
	strings:
		$s0 = {5f 55 5f 58 49 41} // system
		$s1 = {5b 4d 58 4f 44 48 43 4b}//watchdog
		$s2 = {5f 44 49 40 40} // shell
		$s3 = {03 4e 45 42 03 4e 59 5f 55 4e 43 54} // /bin/busybox
	condition:
		all of them
}