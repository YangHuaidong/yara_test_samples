rule Trojan_DDoS_Linux_Gafgyt_Af_20171221111901_895 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.Af"
		threattype = "DDOS"
		family = "Gafgyt"
		hacker = "None"
		refer = "5AF608F9F8AFD44FF03DA0780916B568,31A62C145105621B0D2C97FC3B693E38,10E95BD3048FA059D7526398B6DD8DAB,971CF00781A97E43096E50AC7416E0C6"
		description = "None"
		comment = "None"
		author = "LiuGuangzhu"
		date = "2017-09-07"
	strings:
		$s0 = "cd /tmp; wget"
		$s1 = ".%d.%d"
		$s2 = "SUCCESS| %s:%s:%s"
		$s3 = "ERROR| %s:%s:%s"
		$s4 = "STD <target> <port> <time>"
		$s5 = "STOPPING NETIS SCANNER %s"
		$s6 = "OK| %s"
		$s7 = "cd /tmp || cd /var/system || cd /mnt || cd /lib"
		$s8 = "IP: %s || Port: 23 || Username: %s || Password: %s"
		$s9 = "[ CONNECTED ] IP: %s || Arch Type: %s || Endianness Type: %s]"
		$s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /"
		$s11 = "REPORT %s:%s:%s"
		$s12 = "[F] || IP: %s || Port: 23 || Username: %s || Password: %s"
		$s13 = "rm -rf /tmp/* /var/* /var/run/* /var/tmp/*"
		$s14 = "rm -rf /var/log/wtmp"

	condition:
		5 of them
//($s0 and $s1 and $s2 and $s3 and $s4 and $s5 and $s6) or ($s7 and $s8 and $s9) or ($s10 and $s11 and $s12 and $s13 and $s14) or ($s1 and $s8 and $s11 and ($s10 or ($s13 and $s14)))
}
