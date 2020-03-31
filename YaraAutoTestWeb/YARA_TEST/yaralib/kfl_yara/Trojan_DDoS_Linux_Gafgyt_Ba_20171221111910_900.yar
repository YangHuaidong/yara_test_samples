rule Trojan_DDoS_Linux_Gafgyt_Ba_20171221111910_900 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.Ba"
		threattype = "DDOS"
		family = "Gafgyt"
		hacker = "None"
		refer = "3D8AC0405C7A7028BB1491A1451E5069,E28CDD82AB2BF01335AFC5A94EACA4E0,8863FF7ED92D1085DAF8CFAC60F1257C"
		description = "None"
		comment = "None"
		author = "LiuGuangzhu"
		date = "2017-09-07"
	strings:
		$s0 = "cd /tmp || cd /var/system || cd /mnt || cd /root || cd /"
		$s1 = "WGET FOUND | IP: %s | Type: %s | Version: %s"
		$s2 = "SCANNER"
		$s3 = "[32mSuccessfull Bruteforced [%s] [%s:%s]"
		$s4 = "rm -rf /tmp/* /var/* /var/run/* /var/tmp/*"
		$s5 = "rm -rf /var/log/wtmp"
		$s6 = "/proc/net/route"
		$s7 = ".%d.%d"

	condition:
		(1 or ($s0 and $s1)) and $s2 and $s3 and $s4 and $s5 and $s6 and $s7
}
