rule Trojan_DDoS_Linux_Gafgyt_gm_1165
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.gm"
		threattype = "DDoS"
		family = "Gafgyt"
		hacker = "None"
		refer = "5213C0BF0282DD0DEA950B84E935FE53"
		author = "Luoxuan"
		comment = "None"
		date = "2019-06-13"
		description = "None"
	strings:
		$s0 = {68 6F 6E 65 79 70 6F 74}
		$s1 = {5B 48 50 5D}
		$s2 = {75 67 65 69 31 30}
	condition:
		all of them
}