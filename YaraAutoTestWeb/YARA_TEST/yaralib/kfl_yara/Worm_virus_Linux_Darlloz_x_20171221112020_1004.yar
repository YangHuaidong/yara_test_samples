rule Worm_virus_Linux_Darlloz_x_20171221112020_1004 
{
	meta:
		judge = "black"
		threatname = "Worm[virus]/Linux.Darlloz.x"
		threattype = "virus"
		family = "Darlloz"
		hacker = "None"
		refer = "653e15c9a5aa323102e1d57724b49e6a"
		description = "None"
		comment = "None"
		author = "xc"
		date = "2017-09-26"
	strings:
		$s0 = "/proc/self/exe"
		$s1 = "/etc/init.d/inetd.busybox start"
		$s2 = "iptables -D INPUT -p tcp --dport 32764 -j DROP"
		$s3 = "iptables -A INPUT -p tcp --dport 23 -j DROP"
		$s4 = "/etc/rc.d/init.d/xinetd start"
		$s5 = "iris4000"
		$s6 = "blablablabla"

	condition:
		5 of them
}
