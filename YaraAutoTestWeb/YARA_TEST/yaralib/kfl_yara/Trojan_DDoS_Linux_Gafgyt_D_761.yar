rule Trojan_DDoS_Linux_Gafgyt_D_761
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.D"
		threattype = "DDoS"
		family = "Gafgyt"
		hacker = "None"
		refer = "4E7CF05C2AD296058DCE5A710CDB9F7A"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2017-09-07"
		description = "None"
	strings:
		$s0 = "sh || shell"
		$s1 = "busybox wget || wget"
		$s2 = "My IP: %s"
		$s3 = "BUILD [%s:%s:%d]"
		$s4 = "SCANNER ON | OFF"
		$s5 = "BUILD %s"
		$s6 = "HOLD <ip> <port> <time>"
		$s7 = "JUNK <ip> <port> <time>"
	condition:
		//all of them
		($s0 and $s1 and $s2 and $s3 and $s4) or ($s2 and $s5 and $s6 and $s7)
}