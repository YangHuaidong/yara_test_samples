rule Trojan_DDoS_Linux_Mirai_0x22_770
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Mirai.0x22"
		threattype = "DDoS"
		family = "Mirai"
		hacker = "None"
		refer = "e9e981bf5558bd69f0923d3ab5a4ac27"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2018-09-12"
		description = "None"

	strings:
		$s0 = {51 4a 47 4e 4e} //shell
		$s1 = {47 4c 43 40 4e 47} //enable
		$s2 = {51 5b 51 56 47 4f} //system
		$s3 = {0d 40 4b 4c 0d 40 57 51 5b 40 4d 5a} ///bin/busybox
		$s4 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A"
		
	condition:
		$s0 and $s1 and $s2 and $s3 and not $s4
}