rule Trojan_DDos_Linux_Gafgyt_825_262
{
	meta:
		judge = "black"
		threatname = "Trojan[DDOS]/Linux.Gafgyt.aa"
		threattype = "DDOS"
		family = "Gafgyt"
		hacker = "None"
		refer = "73BAA48D0405A1BF7A121116E56F6726"
		description = "None"
		author = "Fariin"
		date = "2018-11-14"
		comment = "None"
		
	strings:
		$ = "GHP %s Flooding %s"
		$ = "[35;1mLoli Bot"
		$ = "[36;1mIncoming Loli"
	condition:
		all of them
}

