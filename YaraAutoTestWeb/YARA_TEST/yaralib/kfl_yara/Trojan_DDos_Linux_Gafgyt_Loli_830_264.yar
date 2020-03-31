rule Trojan_DDos_Linux_Gafgyt_Loli_830_264
{
	meta:
		judge = "black"
		threatname = "Trojan[DDOS]/Linux.Gafgyt.Loli"
		threattype = "DDOS"
		family = "Gafgyt"
		hacker = "None"
		refer = "DB63528553BB10F82DB39F01201CBD8F"
		description = "None"
		author = "Fariin"
		date = "2018-11-15"
		comment = "None"
		
	strings:
		$s0 = "GHP %s Flooding %s"
		$s1 = "[35;1mLoli Bot"
		$s2 = "[36;1mBruted a Telnet"
	condition:
		all of them
}

