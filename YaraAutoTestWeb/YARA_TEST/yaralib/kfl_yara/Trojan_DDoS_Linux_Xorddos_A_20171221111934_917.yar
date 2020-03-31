rule Trojan_DDoS_Linux_Xorddos_A_20171221111934_917 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Xorddos.A"
		threattype = "DDOS"
		family = "Xorddos"
		hacker = "None"
		refer = "cfc700ea49f3e4e3abb0e15b316b4e3a,a5e15e3565219d28cdeec513036dcd53,59423d0f4d89ca8ea6dd17275d64efa3,38ad29dec890f889aa8889efec400390,c3961556f6c1a98726a37d8976f22d5d,e9db2bcc3678779114f8ed31c875cbd3,89006f4768662964a9ce1615fa151109,a7c5f33750b9f3602c03ca1f4c2c346b,0952f598adb1160d9312403ce6035b02"
		description = "None"
		comment = "None"
		author = "LiuGuangzhu"
		date = "2017-08-19"
	strings:
		$s0 = "/etc/init.d/%s"
		$s1 = "/proc/%d/exe"
		$s2 = "/etc/rc%d.d/S90%s"
		$s3 = "/etc/rc.d/rc%d.d/S90%s"
		$s4 = "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:/usr/X11R6/bin"
		$s5 = "/etc/cron.hourly/"

	condition:
		all of them
}
