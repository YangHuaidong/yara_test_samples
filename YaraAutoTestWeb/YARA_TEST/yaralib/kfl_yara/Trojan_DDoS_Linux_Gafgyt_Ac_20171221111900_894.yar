rule Trojan_DDoS_Linux_Gafgyt_Ac_20171221111900_894 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.Ac"
		threattype = "DDOS"
		family = "Gafgyt"
		hacker = "None"
		refer = "eee3df6e3e0d36332445f5cd0942a4b2,e7cea1fa95185e833a7c763d9399a88b,bee8b9f297b35b2da3a663500aaa5f33,057784A2FAF7ADFE3AE55B3A3977AB9C"
		description = "None"
		comment = "None"
		author = "LiuGuangzhu"
		date = "2017-08-18"
	strings:
		$s0 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /"
		$s1 = "assword"
		$s2 = "My IP: %s"
		$s3 = "REPORT %s:%s:%s"
		$s4 = "SCANNER ON | OFF"
		$s5 = "REMOVING PROBE"
		$s6 = "PROBING"
		$s7 = "[%s:%s:%s]"
		$s8 = "rm -rf /var/log/wtmp"
		$s9 = "BUILD %s"
		$s10 = "SELFREP ON | OFF"

	condition:
		$s0 and $s1 and $s2 and (($s3 and $s4 and $s5 and $s6) or ($s7 and $s8 and $s9 and $s10))
}
