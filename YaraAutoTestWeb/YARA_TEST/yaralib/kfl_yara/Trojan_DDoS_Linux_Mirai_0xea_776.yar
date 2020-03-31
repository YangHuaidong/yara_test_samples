rule Trojan_DDoS_Linux_Mirai_0xea_776
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Mirai.0xea"
		threattype = "DDoS"
		family = "Mirai"
		hacker = "None"
		refer = "455b3a20fae6e97af04b09f0aabc9025"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2018-09-12"
		description = "None"

	strings:
		$s0 = {99 82 8f 86 86} //shell
		$s1 = {8f 84 8b 88 86 8f} //enable
		$s2 = {99 93 99 9e 8f 87} //system
		$s3 = {c5 88 83 84 c5 88 9f 99 93 88 85 92} ///bin/busybox
		$s4 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A"
		
	condition:
		$s0 and $s1 and $s2 and $s3 and not $s4
}