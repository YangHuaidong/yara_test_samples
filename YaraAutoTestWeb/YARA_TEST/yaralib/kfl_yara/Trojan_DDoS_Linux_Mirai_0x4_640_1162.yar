rule Trojan_DDoS_Linux_Mirai_0x4_640_1162
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Mirai.0x4.640"
		threattype = "DDoS"
		family = "Mirai"
		hacker = "None"
		refer = "89903aec9ba7f858115a58c0ea756d19"
		author = "Luoxuan"
		comment = "None"
		date = "2019-05-13"
		description = "None"

	strings:
		$s0 = {63 65 69 61}//game
		$s1 = {66 71 6d 68 60} //build
		$s2 = {6f 65 68 6b 6a}// kalon
		
	condition:
		all of them
}