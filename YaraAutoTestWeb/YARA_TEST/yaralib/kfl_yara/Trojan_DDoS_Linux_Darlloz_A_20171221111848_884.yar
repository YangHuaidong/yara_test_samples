rule Trojan_DDoS_Linux_Darlloz_A_20171221111848_884 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Darlloz.A"
		threattype = "DDOS"
		family = "Darlloz"
		hacker = "none"
		refer = "01ad371d727a5aede23a6afd803f5abe,59b7cf3f8b0f765590207d5e40a6f48b,fc71e8e02700bade55e0733ff6ce8a2d,b003af27251d78ca340398929e094dad,dfeb77cb0ba28ac3ba4be55d7bc91fad"
		description = "none"
		comment = "none"
		author = "HuangYY"
		date = "2016-10-10"
	strings:
		$s0 = "rm -rf /var/run/.zollard"
		$s1 = "mkdir -p /var/run/.zollard"
		$s2 = "cd /var/run/.zollard"
		$s3 = "/etc/rc.d/init.d/xinetd start"
		$s4 = "/etc/init.d/inetd.busybox stop"
		$s5 = "/var/run/.lamorte/lamorte.pid"
		$s6 = "/media/cmd.so"
		$s7 = "/ffp/bin/wget"
		$s8 = "wget -P /tmp http://"

	condition:
		all of them
}
