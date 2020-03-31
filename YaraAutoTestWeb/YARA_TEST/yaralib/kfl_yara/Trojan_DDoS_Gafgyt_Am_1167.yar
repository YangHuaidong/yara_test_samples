rule Trojan_DDoS_Linux_Gafgyt_Am_1167
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.Am"
		threattype = "DDoS"
		family = "Gafgyt"
		hacker = "None"
		refer = "248ACB2E658A7AC5FD6FBC2380AF7323"
		author = "Luoxuan"
		comment = "None"
		date = "2019-06-13"
		description = "None"
	strings:
		$s0 = {5B 31 3B 33 31 6D 41 6D 6E 65 73 69 61 1B 5B 31 3B 33 37 6D 5B 1B 5B 31 3B 33 31 6D 56 31 2E 30 1B 5B 31 3B 33 37 6D 5D 1B 5B 31 3B 33 31 6D 2D 2D 3E 1B 5B 31 3B 33 37 6D 5B 1B 5B 30 3B 33 36 6D 25 73 1B 5B 31 3B 33 37 6D 5D 1B 5B 31 3B 33 31 6D 2D 2D 3E 1B 5B 31 3B 33 37 6D 5B 1B 5B 30 3B 33 36 6D 25 73 1B 5B 31 3B 33 37 6D 5D 1B 5B 31 3B 33 31 6D 2D 2D 3E 1B 5B 31 3B 33 37 6D 5B 1B 5B 30 3B 33 36 6D 25 73 1B 5B 31 3B 33 37 6D 5D 1B 5B 31 3B 33 31 6D 2D 2D 3E 1B 5B 31 3B 33 37 6D 5B 1B 5B 30 3B 33 36 6D 25 73 1B 5B 31 3B 33 37 6D 5D}
	condition:
		all of them
}