rule Trojan_DDoS_Linux_Gafgyt_Av_20171221111905_898 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.Av"
		threattype = "DDOS"
		family = "Gafgyt"
		hacker = "None"
		refer = "2AD0275F7EBEF9DAE4A089D790B83C34"
		description = "None"
		comment = "None"
		author = "LiuGuangzhu"
		date = "2017-09-07"
	strings:
		$s0 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /"
		$s1 = "[37m] Bruted [%s] [%s:%s]"
		$s2 = "/proc/%ld/cmdline"
		$s3 = "/proc/%i/exe"
		$s4 = "[37m] Bots Are On"

	condition:
		all of them
}
