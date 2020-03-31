rule Trojan_DDoS_Linux_Gafgyt_Cor_1164
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.Cor"
		threattype = "DDoS"
		family = "Gafgyt"
		hacker = "None"
		refer = "248ACB2E658A7AC5FD6FBC2380AF7323"
		author = "Luoxuan"
		comment = "None"
		date = "2019-06-13"
		description = "None"
	strings:
		$s0 = {5B 39 36 6D 5B 25 73 5D 20 1B 5B 39 37 6D 43 6F 6E 6E 65 63 74 65 64}
		$s1 = {6D 69 72 61 69}
		$s2 = {73 65 72 6e 61 6D 65}
	condition:
		all of them
}