rule Trojan_DDoS_Linux_Gafgyt_Av_755
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.Av"
		threattype = "DDoS"
		family = "Gafgyt"
		hacker = "None"
		refer = "2AD0275F7EBEF9DAE4A089D790B83C34"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2017-09-07"
		description = "None"
	strings:
		$s0 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /"
		$s1 = "[37m] Bruted [%s] [%s:%s]"
		$s2 = "/proc/%ld/cmdline"
		$s3 = "/proc/%i/exe"
		$s4 = "[37m] Bots Are On"
	condition:
		all of them
}