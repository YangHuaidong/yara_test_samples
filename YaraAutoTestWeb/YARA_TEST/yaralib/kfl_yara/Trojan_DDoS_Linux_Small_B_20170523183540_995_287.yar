rule Trojan_DDoS_Linux_Small_B_20170523183540_995_287 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Small.B"
		threattype = "DDOS"
		family = "Small"
		hacker = "None"
		refer = "14B02B5B4080022B3BC90134346E087C"
		description = "None"
		comment = "None"
		author = "cjf"
		date = "2017-05-09"
	strings:
		$s0 = "Vadim patched by paxi"
		$s1 = "bad port number"
		$s2 = "Unknown host"
		$s3 = "0123456789"

	condition:
		all of them
}
