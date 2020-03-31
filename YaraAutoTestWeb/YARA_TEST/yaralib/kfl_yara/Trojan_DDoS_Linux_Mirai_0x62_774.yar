rule Trojan_DDoS_Linux_Mirai_0x62_774
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Mirai.0x62"
		threattype = "DDoS"
		family = "Mirai"
		hacker = "None"
		refer = "dec3181eeca733f890f8f80673b261eb"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2018-09-12"
		description = "None"

	strings:
		$s0 = {11 0a 07 0e 0e} //shell
		$s1 = {07 0c 03 00 0e 07} //enable
		$s2 = {11 1b 11 16 07 0f} //system
		$s3 = {4d 00 0b 0c 4d 00 17 11 1b 00 0d 1a} ///bin/busybox
		$s4 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A"
		
	condition:
		$s0 and $s1 and $s2 and $s3 and not $s4
}