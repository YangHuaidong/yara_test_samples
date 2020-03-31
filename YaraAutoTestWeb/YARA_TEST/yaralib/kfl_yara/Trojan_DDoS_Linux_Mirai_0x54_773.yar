rule Trojan_DDoS_Linux_Mirai_0x54_773
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Mirai.0x54"
		threattype = "DDoS"
		family = "Mirai"
		hacker = "None"
		refer = "aa77130dd5d577b526753c1941aa1326"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2018-09-12"
		description = "None"

	strings:
		$s0 = {27 3C 31 38 38} //shell
		$s1 = {31 3A 35 36 38 31} //enable
		$s2 = {27 2D 27 20 31 39} //system
		$s3 = {7B 36 3D 3A 7B 36 21 27 2D 36 3B 2C} ///bin/busybox
		$s4 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A"
		
	condition:
		$s0 and $s1 and $s2 and $s3 and not $s4
}