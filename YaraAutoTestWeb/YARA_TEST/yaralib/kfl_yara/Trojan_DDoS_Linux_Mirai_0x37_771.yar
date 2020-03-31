rule Trojan_DDoS_Linux_Mirai_0x37_771
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Mirai.0x37"
		threattype = "DDoS"
		family = "Mirai"
		hacker = "None"
		refer = "b2f658b575975fa94ac1042425f025cd"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2018-09-12"
		description = "None"

	strings:
		$s0 = {44 5f 52 5b 5b} //shell
		$s1 = {52 59 56 55 5b 52} //enable
		$s2 = {44 4e 44 43 52 5a} //system
		$s3 = {18 55 5e 59 18 55 42 44 4e 55 58 4f} ///bin/busybox
		$s4 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A"
		
	condition:
		$s0 and $s1 and $s2 and $s3 and not $s4
}