rule Trojan_DDoS_Linux_Mirai_0xeal_777
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Mirai.0xeal"
		threattype = "DDoS"
		family = "Mirai"
		hacker = "None"
		refer = "1e4d4c07bca3954643550a93042d0494"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2018-09-12"
		description = "None"

	strings:
		$s0 = {c5 8f 9e 89 c5 98 8f 99 85 86 9c c4 89 85 84 8c} ///etc/resolv.conf
		$s1 = {84 8b 87 8f 99 8f 98 9c 8f 98} //nameserver
		$s2 = {c5 8e 8f 9c c5 9d 8b 9e 89 82 8e 85 8d} ///dev/watchdog
		$s3 = {c5 9a 98 85 89 c5 84 8f 9e c5 9e 89 9a} ///proc/net/tcp
		$s4 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A"
		
	condition:
		$s0 and $s1 and $s2 and $s3 and not $s4
}