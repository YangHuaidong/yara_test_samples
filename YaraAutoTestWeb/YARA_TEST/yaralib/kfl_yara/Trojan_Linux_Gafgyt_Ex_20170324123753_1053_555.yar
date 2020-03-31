rule Trojan_Linux_Gafgyt_Ex_20170324123753_1053_555 
{
	meta:
		judge = "black"
		threatname = "Trojan/Linux.Gafgyt.Ex"
		threattype = "DDOS"
		family = "Gafgyt"
		hacker = "None"
		refer = "040f2a52bffc3c219958d9d45160333d"
		description = "None"
		comment = "None"
		author = "LGZ"
		date = "2017-01-06"
	strings:
		$s1 = "BUILD %s"
		$s2 = "/proc/net/route"
		$s3 = "mainCommSock"
		$s4 = "getRandomIP"
		$s5 = "sendUDP"
		$s6 = "My IP: %s"
		$s7 = "getRandomPublicIP"
		$s8 = "sendTCP"
		$s9 = "SCANNER"
		$s10 = "gayfgt"
		$s11 = "getOurIP"
		$s12 = "KILLATTK"
		$s13 = "libc/sysdeps/linux/mips"

	condition:
		5 of them
}
