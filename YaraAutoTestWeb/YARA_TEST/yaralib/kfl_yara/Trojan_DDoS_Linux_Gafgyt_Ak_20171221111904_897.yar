rule Trojan_DDoS_Linux_Gafgyt_Ak_20171221111904_897 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.Ak"
		threattype = "DDOS"
		family = "Gafgyt"
		hacker = "None"
		refer = "70ED0B521767256EBF82F47E2EE3CF6F,288AB38204934B08274FFB6C736572AA"
		description = "None"
		comment = "None"
		author = "LiuGuangzhu"
		date = "2017-09-07"
	strings:
		$s0 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /"
		$s1 = ".%d.%d"
		$s2 = "rm -rf /tmp/* /var/* /var/run/* /var/tmp/*"
		$s3 = "rm -rf /var/log/wtmp"
		$s4 = "REPORT %s:%s:%s"
		$s5 = "My IP: %s"
		$s6 = "SCANNER ON | OFF"
		$s7 = "BUILD %s:%s"

	condition:
		all of them
}
