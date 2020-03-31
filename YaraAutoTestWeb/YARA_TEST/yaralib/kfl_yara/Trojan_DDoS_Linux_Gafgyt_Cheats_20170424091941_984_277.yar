rule Trojan_DDoS_Linux_Gafgyt_Cheats_20170424091941_984_277 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.Cheats"
		threattype = "DDOS"
		family = "Gafgyt"
		hacker = "None"
		refer = "3722857a5c87eab1202bb2506b5d22a4"
		description = "None"
		comment = "None"
		author = "DJW"
		date = "2017-04-12"
	strings:
		$s0 = "Cheats.sh"
		$s1 = "5.152.211.70"
		$s2 = "/usr/bin/python"
		$s3 = "bttiaessroatsst2"
		$s4 = "ftp11.sh"
		$s5 = "tftp22.sh"
		$s6 = "tftp11.sh"
		$s7 = "/proc/net/route"
		$s8 = "Illegal seek"

	condition:
		5 of them
}
