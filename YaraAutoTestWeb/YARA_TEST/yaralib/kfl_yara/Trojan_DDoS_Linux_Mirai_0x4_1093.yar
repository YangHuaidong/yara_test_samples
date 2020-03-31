rule Trojan_DDoS_Linux_Mirai_0x4_1093
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Mirai.0x4"
		threattype = "DDoS"
		family = "Mirai"
		hacker = "None"
		refer = "8d92fa7c6aa019247e02919cbda322c0"
		author = "Luoxuan"
		comment = "None"
		date = "2019-04-10"
		description = "None"
	strings:
		$s0 = {77 7d 77 70 61 69} // system
		$s1 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A"
		$s2 = {77 6c 61 68 68} // shell
		$s3 = {2B 66 6D 6A 2B 66 71 77 7D 66 6B 7C} // /bin/busybox
	condition:
		$s0 and $s3 and $s2 and not $s1
}