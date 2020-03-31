rule Trojan_Linux_Mirai_Scan_20170424091948_1062_562 
{
	meta:
		judge = "black"
		threatname = "Trojan/Linux.Mirai.Scan"
		threattype = "DDOS"
		family = "Mirai"
		hacker = "None"
		refer = "d4a78932abbd6fdff486e41316ffc3dd"
		description = "None"
		comment = "None"
		author = "DJW"
		date = "2017-04-12"
	strings:
		$s0 = "miraiscan"
		$s1 = "Mirai-brute"
		$s2 = "access.c"
		$s3 = "getbinaries.sh"
		$s4 = "kill.c"
		$s5 = "PRIVMSG %s"
		$s6 = "mirai"
		$s7 = "nsackflood"
		$s8 = "synflood"
		$s9 = "ackflood"

	condition:
		5 of them
}
