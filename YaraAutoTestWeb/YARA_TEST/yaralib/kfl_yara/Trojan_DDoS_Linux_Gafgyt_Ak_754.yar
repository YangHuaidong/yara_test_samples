rule Trojan_DDoS_Linux_Gafgyt_Aj_754
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.Aj"
		threattype = "DDoS"
		family = "Gafgyt"
		hacker = "None"
		refer = "70ED0B521767256EBF82F47E2EE3CF6F,288AB38204934B08274FFB6C736572AA"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2017-09-07"
		description = "None"
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