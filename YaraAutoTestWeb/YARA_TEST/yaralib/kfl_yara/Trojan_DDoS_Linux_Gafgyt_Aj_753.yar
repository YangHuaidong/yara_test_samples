rule Trojan_DDoS_Linux_Gafgyt_Aj_753
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.Aj"
		threattype = "DDoS"
		family = "Gafgyt"
		hacker = "None"
		refer = "149e2c7c1af4cdea70511d4aea25daaf,a6267e55e82c6d9199275bc50f0e6f0a,F1A82109687A20447EA4EF3A43290DE7,1D25F876FDE2807C7358B8EC1126CBC7"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2017-09-07"
		description = "None"
	strings:
		$s0 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /"
		$s1 = "SCANNER"
		$s2 = "My IP: %s"
		$s3 = ".%d.%d"
		$s4 = "ping %s -s %s -i %s -w %s"
		$s5 = "HTTP %s Flooding %s:%d for %d seconds"
		$s6 = "BUILD [%s:%s:%d]"
		$s7 = "[Success] [Login Found]- %s:%s:%s"
		$s8 = "[CONNECTED] [%s] [%s]"
		$s9 = "cd /tmp || cd /var/tmp"
	condition:
		($s0 or $s9) and $s1 and $s2 and $s3 and ($s4 or ($s5 and $s6) or ($s5 and $s7 and $s8))
}