rule Trojan_DDoS_Linux_Tsunami_B_787
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Tsunami.B"
		threattype = "DDoS"
		family = "Tsunami"
		hacker = "None"
		refer = "168b8b312814921d7ffe7f81e5455c4a,0eac2e6642e27c9aed487eab45a4210b"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2017-08-21"
		description = "None"

	strings:
		$s0 = "NOTICE %s"
		$s1 = "NICK %s"
		$s2 = "%s : USERID : UNIX : %s"
		$s3 = "MODE %s"
		$s4 = "JOIN %s :%s"
		$s5 = "PONG %s"
		$s6 = "TSUNAMI"
		$s7 = "export PATH=/bin:/sbin:/usr/bin:/usr/local/bin:/usr/sbin;%s"
		$s8 = "PRIVMSG"
	condition:
		$s0 and $s1 and $s2 and $s3 and $s4 and $s5 and (($s6 and $s7) or $s8)
}