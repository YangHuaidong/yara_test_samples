rule Trojan_DDoS_Linux_Ddostf_A_741
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Ddostf.A"
		threattype = "DDoS"
		family = "Ddostf"
		hacker = "None"
		refer = "5e362773eed4791238293a07a6ce4550,71db25baa1e726511913256ef93ab255,1410735ae17d8b989a3160cd73d2e89f,7dcef44d586e28e9b5f595adc93991e5,6bc116f9f29166354d41a3de3b4dc76f,d388191060ba25ab259a9a7359966a32"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2017-08-20"
		description = "None"

	strings:
		$s0 = "%d Kb/bps|%d%%"
		$s1 = "TCP_KEEPINTVL"
		$s2 = "TCP_KEEPCNT"
		$s3 = "mv %s/%s /etc/%s"
		$s4 = "sed -i -e '/%s/d' /etc/rc.local"
		$s5 = "sed -i -e '2 i/etc/%s reboot' /etc/rc.local"
		$s6 = "sed -i -e '2 i/etc/%s start' /etc/rc.d/rc.local"
		$s7 = "sed -i -e '2 i/etc/%s start' /etc/init.d/boot.local"
		$s8 = "8AELDt"
		$s9 = "TF- Linux kernel"
		$s10 = "Genut"
	condition:
		//($s0 or $s1) and $s2 and $s3 and $s4 and $s5 and $s6 and $s7 and $s8 and $s9
		$s0 and $s1 and $s2 and (($s3 and $s4 and $s5 and $s6 and $s7) or ($s8 and $s9) or $s10)
}