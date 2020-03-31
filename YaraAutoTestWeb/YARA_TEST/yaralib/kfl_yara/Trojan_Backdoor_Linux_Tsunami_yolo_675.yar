rule Trojan_Backdoor_Linux_Tsunami_yolo_675
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Linux.Tsunami.yolo"
		threattype = "Backdoor"
		family = "Tsunami"
		hacker = "None"
		refer = "541710352c2604a0d9fc34f54d629df9"
		author = "xc"
		comment = "None"
		date = "2017-08-17"
		description = "None"
	strings:
		$s0 = "Majors Bitch"
		$s1 = "npxXoudifFeEgGaACScs"
		$s2 = "/usr/dict/words"
		$s3 = "[bitches]"
		$s4 = "#yolo"
		$s5 = "hlLjztqZ"
	condition:
		all of them
}