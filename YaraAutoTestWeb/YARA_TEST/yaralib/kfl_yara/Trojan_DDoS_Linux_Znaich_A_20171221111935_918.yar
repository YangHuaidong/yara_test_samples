rule Trojan_DDoS_Linux_Znaich_A_20171221111935_918 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Znaich.A"
		threattype = "DDOS"
		family = "Znaich"
		hacker = "None"
		refer = "00f300d3ad660c920fbbe323b1ca6fb0,46851b86af2e32dbbf26547faec2c39c,5f1faea3cc1ba5eaed7d7d671b638840,855d547036b367724ffeba679ea8d99a,8c44cf173f2e07dbfeb9a216d8de0e2f,bbd027b69ef7f41037a25a1619569c0e,462e213db41e6d2d4080103badd5cc08,a1518615cd3edb8c1118c9f9791cb858,135944f7b1681dcd6ab0e02407a7975c,6a15e70fa7b7c71f53769fa886083f29"
		description = "None"
		comment = "None"
		author = "LiuGuangZhu"
		date = "2017-08-19"
	strings:
		$s0 = "%d %.2d %.2d.%.3d %c %d %.2d %.2d.%.3d %c %d.%.2dm %sm %sm %sm"
		$s1 = "key_tag= %u"
		$s2 = "0x%04x %u %u"
		$s3 = "%s %d %d %lu"
		$s4 = "%04d%02d%02d%02d%02d%02d"
		$s5 = "%ld.%.2ld"
		$s6 = "/proc/self/task/%u/comm"
		$s7 = "Mode(SYN) Target:%s:%d"
		$s8 = "MODE(UDP) Target:%s:%d"
		$s9 = "MODE(ICMP) Taregt:%s:%d"
		$s10 = "MODE(DNS) Target:%s"
		$s11 = "Cmd Arrive [%s]"

	condition:
		//all of them
($s0 and $s1 and $s2 and $s3 and $s4 and $s5 and $s6) or ($s7 and $s8 and $s9 and $s10 and $s11)
}
