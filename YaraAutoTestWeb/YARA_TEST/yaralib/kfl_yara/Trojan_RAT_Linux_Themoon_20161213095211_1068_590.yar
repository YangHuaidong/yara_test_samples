rule Trojan_RAT_Linux_Themoon_20161213095211_1068_590 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Linux.Themoon"
		threattype = "rat"
		family = "Themoon"
		hacker = "None"
		refer = "c44f2d8ad37c18ea84a99db584d6992d,514b7da4b811da11fe7033aea155dba6"
		description = "None"
		comment = "None"
		author = "sxy"
		date = "2016-11-10"
	strings:
		$s0 = "46.148.18.0/24"
		$s1 = "185.56.30.0/24"
		$s2 = "217.79.182.0/24"
		$s3 = "85.114.135.0/24"
		$s4 = "95.213.143.0/24"
		$s5 = "185.53.8.0/24"
		$s6 = ".nttpd"

	condition:
		all of them
}
