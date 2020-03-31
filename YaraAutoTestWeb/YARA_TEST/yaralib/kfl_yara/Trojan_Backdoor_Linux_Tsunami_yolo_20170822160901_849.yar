rule Trojan_Backdoor_Linux_Tsunami_yolo_20170822160901_849 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Linux.Tsunami.yolo"
		threattype = "BackDoor"
		family = "Tsunami"
		hacker = "None"
		refer = "541710352c2604a0d9fc34f54d629df9"
		description = "None"
		comment = "None"
		author = "xc"
		date = "2017-08-17"
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
