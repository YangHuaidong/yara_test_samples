rule Trojan_DDoS_Linux_Ddostf_E_20171221111850_886 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Ddostf.E"
		threattype = "DDOS"
		family = "Ddostf"
		hacker = "None"
		refer = "64bef2a0be744531e632bb61516e0a74"
		description = "None"
		comment = "None"
		author = "LiuGuangzhu"
		date = "2017-09-21"
	strings:
		$s0 = "%dKb/bps|%d%%"
		$s1 = "TCP_KEEPINTVL"
		$s2 = "TCP_KEEPCNT"
		$s3 = "SYN-Flow"
		$s4 = "mv %s/%s /etc/%s"
		$s5 = "sed -i -e '/%s/d' /etc/rc.local"
		$s6 = "sed -i -e '2 i/etc/%s reboot' /etc/rc.local"
		$s7 = "sed -i -e '2 i/etc/%s start' /etc/rc.d/rc.local"
		$s8 = "sed -i -e '2 i/etc/%s start' /etc/init.d/boot.local"

	condition:
		all of them
//$s0 and $s1 and $s2 and (($s3 and $s4 and $s5 and $s6 and $s7) or ($s8 and $s9) or $s10)
}
