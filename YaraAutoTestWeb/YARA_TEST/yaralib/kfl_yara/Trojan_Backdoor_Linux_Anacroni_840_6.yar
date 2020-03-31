rule Trojan_Backdoor_Linux_Anacroni_840_6
{
	meta:
		judge = "black"
		threatname = "Trojan[BackDoor]/Linux.Anacroni"
		threattype = "BackDoor"
		family = "Anacroni"
		hacker = "None"
		refer = "bcc79f90cf253c6fa6be10dcaec0f4ec"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2018-11-22"
		description = "None"

	strings:		
		$s0 = "%s %u %u %u %u"
		$s1 = "%02x%02x%02x%02x%02x%02x"
		$s2 = "VERSONEX:Linux-%s|%d|"
		$s3 = "INFO:0.%d%%|%s"
		$s4 = "%.2f Mbps"
		$s5 = "/etc/init.d/anacroni"
		$s6 = "/bin/anacroni"
		$s7 = "touch -r /bin/sh /etc/init.d/anacroni"
		$s8 = "chkconfig --add anacroni"
	condition:
		all of them
}