rule Trojan_DDoS_Linux_Mirai_0xb4_775
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Mirai.0xb4"
		threattype = "DDoS"
		family = "Mirai"
		hacker = "None"
		refer = "416533316ee5a1c5275ed414bbb8f0d1"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2018-09-13"
		description = "None"

	strings:
		$s0 = {c7 dc d1 d8 d8} //shell
		$s1 = {d1 da d5 d6 d8 d1} //enable
		$s2 = {c7 cd c7 c0 d1 d9} //system
		$s3 = {9b d6 dd da 9b d6 c1 c7 cd d6 db cc} ///bin/busybox
		$s4 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A"
		
	condition:
		$s0 and $s1 and $s2 and $s3 and not $s4
}