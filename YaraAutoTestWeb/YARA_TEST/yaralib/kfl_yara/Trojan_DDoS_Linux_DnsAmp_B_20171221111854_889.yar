rule Trojan_DDoS_Linux_DnsAmp_B_20171221111854_889 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.DnsAmp.B"
		threattype = "DDOS"
		family = "DnsAmp"
		hacker = "None"
		refer = "effe268d22850129306cf371f1b91796"
		description = "None"
		comment = "None"
		author = "LiuGuangZhu"
		date = "2017-08-22"
	strings:
		$s0 = "chattr -i /etc/crontab"
		$s1 = "chmod +w /etc/crontab"
		$s2 = "sed -i '/%s/d' /etc/crontab"
		$s3 = "eth0:%Lu %Lu %Lu %Lu %Lu %Lu %Lu %Lu %Lu"
		$s4 = "INFO:%d|%d"
		$s5 = "VERS0NEX:%s|%d * %dMhz/%dMb"

	condition:
		all of them
}
