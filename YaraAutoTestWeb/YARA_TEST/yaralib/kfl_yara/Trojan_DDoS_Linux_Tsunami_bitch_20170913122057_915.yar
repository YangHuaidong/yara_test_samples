rule Trojan_DDoS_Linux_Tsunami_bitch_20170913122057_915 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Tsunami.bitch"
		threattype = "DDOS"
		family = "Tsunami"
		hacker = "None"
		refer = "1c5dfd72d33518df9ae07880d89cc2fb"
		description = "None"
		comment = "None"
		author = "xc"
		date = "2017-08-31"
	strings:
		$s0 = "[mybitches]"
		$s1 = "Majors Bitch"
		$s2 = "npxXoudifFeEgGaACScs"
		$s3 = "hlLjztqZ"
		$s4 = "/etc/config/resolv.conf"
		$s5 = "/dev/null"
		$s6 = "domain"
		$x0 = "/usr/dict/words"
		$x1 = "#romesh"
		$x2 = "sdyslrsgrrseydsdyskeyytmseyeekmsenedgedys"
		$x3 = "tmedskdedrrdrdreekedyydsyrdrstdgteddddlesnettreddnetdntssegeeerdde"
		$x4 = "bbbttiaessraasst"
		$x5 = "makestring"
		$x6 = "6969"
		$x7 = "/proc/net/route"
		$x8 = "/usr/bin/sshd"
		$a0 = "[UNK] Attacking"
		$a1 = "[STD] Attacking"
		$a2 = "[FIN] Attacking"
		$a3 = "[RST] Attacking"
		$a4 = "[PSH] Attacking"
		$a5 = "[ACK] Attacking"
		$a6 = "[SYN] Attacking"
		$a7 = "[TCP] Attacking"
		$a8 = "[UDP] Attacking"

	condition:
		8 of them
}
