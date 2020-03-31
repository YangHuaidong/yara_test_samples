rule Trojan_DDoS_Linux_Gafgyt_Az_757
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.Az"
		threattype = "DDoS"
		family = "Gafgyt"
		hacker = "None"
		refer = "0D168983B7E85808CC92D8E6295832FA,BC5E88C02A22A0F29464BB8B8149CBAE"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2017-09-07"
		description = "None"
	strings:
		$s0 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /"
		$s1 = "[31m[Bash-Lite]"
		$s2 = "[32mConnected [%s] [%s:%s]"
		$s3 = "BUILD %s"
		$s4 = ".%d.%d"
		$s5 = "cd /tmp || cd /var/run || rm -f *"
		$s6 = "REPORT %s:%s:%s"
		$s7 = "busybox" nocase
		$s8 = "/bin/sh"
		$s9 = "/etc/rc.d/rc.local"
		$s10 = "/etc/rc.conf"
	condition:
		5 of them
		//($s0 and $s1 and $s2 and $s3 and $s4) or ($s5 and $s6 and $s7) or ($s0 and $s8 and $s9 and $s10) or ($s0 and $s6 and $s7 and $s8)
}