rule Trojan_DDoS_Linux_Mirai_0x22_1_1076
{
	meta:
		judge = "black"
		threatname = "Trojan[DDos]/Linux.Mirai.0x22.1"
		threattype = "DDoS"
		family = "Mirai"
		hacker = "None"
		refer = "e08153fbf70ab67d01250fe25ab6262c"
		author = "Luoxuan"
		comment = "None"
		date = "2019-03-20"
		description = "None"

	strings:
		$s0 = {0D 40 4B 4C 0D 40 57 51 5B 40 4D 5A 02 6F 6B 70 63 6B} ///bin/busybox MIRAI
		$s1 = {0D 40 4B 4C 0D 40 57 51 5B 40 4D 5A 02 49 4B 4E 4E 02 0F 1B} ///bin/busybox kill -9
		$s2 = {51 4A 47 4E 4E} //shell
		
	condition:
		all of them
}