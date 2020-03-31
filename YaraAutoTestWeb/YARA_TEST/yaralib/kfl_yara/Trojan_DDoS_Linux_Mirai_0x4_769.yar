rule Trojan_DDoS_Linux_Mirai_0x4_769
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Mirai.0x4"
		threattype = "DDoS"
		family = "Mirai"
		hacker = "None"
		refer = "00ee64a96da111d73bcd7eab652179ba,02375b85179054da2d8352cece8ef4d5,101011c4de7c0a53716212cfba366afd"
		author = "Fariin"
		comment = "None"
		date = "2018-11-27"
		description = "None"

	strings:
		$s0 = {77 7D 77 70 61 69}//system
		$s1 = {68 6D 6A 71 7C 77 6C 61 68 68} //linuxshell
		$s2 = {2B 66 6D 6A 2B 66 71 77 7D 66 6B 7C}// /bin/busybox
		$s3 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A"
		
	condition:
		$s0 and $s1 and $s2 and not $s3
}