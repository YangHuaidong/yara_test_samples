rule Trojan_DDoS_Linux_Mirai_0x45_772
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Mirai.0x45"
		threattype = "DDoS"
		family = "Mirai"
		hacker = "None"
		refer = "eaba1e899d192850bca1a7e809e83e9e"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2018-09-12"
		description = "None"

	strings:
		$s0 = {36 2d 20 29 29} //shell
		$s1 = {20 2b 24 27 29 20} //enable
		$s2 = {36 3c 36 31 20 28} //system
		$s3 = {6a 27 2c 2b 6a 27 30 36 3c 27 2a 3d} ///bin/busybox
		$s4 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A"
		
	condition:
		$s0 and $s1 and $s2 and $s3 and not $s4
}