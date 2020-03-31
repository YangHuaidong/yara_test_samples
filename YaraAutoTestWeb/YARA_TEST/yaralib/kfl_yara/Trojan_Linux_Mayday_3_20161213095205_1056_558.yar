rule Trojan_Linux_Mayday_3_20161213095205_1056_558 
{
	meta:
		judge = "black"
		threatname = "Trojan/Linux.Mayday"
		threattype = "DDOS"
		family = "Mayday"
		hacker = "None"
		refer = "6663474ecdc8100313ea26828c3f5b36,b02c796c3ec00f1d7bd5a1771c042a36,385c946e31449e654fe0bca1b230c979"
		description = "Chicken_mm"
		comment = "None"
		author = "zhoufenyan"
		date = "2016-06-14"
	strings:
		$s0 = "11CAttackBase"
		$s1 = "13CPacketAttack"
		$s2 = "10CAttackUdp"
		$s3 = "10CAttackSyn"
		$s4 = "10CAttackDns"
		$s5 = "10CTcpAttack"
		$s6 = "9CAttackCc"

	condition:
		4 of them
}
