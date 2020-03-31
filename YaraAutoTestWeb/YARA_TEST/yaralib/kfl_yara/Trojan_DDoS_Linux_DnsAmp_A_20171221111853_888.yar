rule Trojan_DDoS_Linux_DnsAmp_A_20171221111853_888 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.DnsAmp.A"
		threattype = "DDOS"
		family = "DnsAmp"
		hacker = "None"
		refer = "013b0f9bee7e745d2292b8c933b73eb4,1a75790687b0c8bee579dd5d7a4368e0,1e15238ef270513b3dd5645c98e4d15e,2d57344193b8c4d6e7f0dcf827d755b1,8800072b4b64d8ddf92419c8277d7136,e0b7ef909e9d250091cb94a9b01ad518,b3d227bada3e4d35dac0a53b373be50a,3caba1703d936e8a9c9799f14aa77145"
		description = "None"
		comment = "None"
		author = "LiuGuangZhu"
		date = "2017-08-21"
	strings:
		$s0 = "Hacker"
		$s1 = "VERSONEX:%s|%d|%d|%s"
		$s2 = "eth0:%Lu %Lu %Lu %Lu %Lu %Lu %Lu %Lu %Lu"
		$s3 = "/etc/rc.d/rc2.d/S99selinux"
		$s4 = "/etc/rc2.d/S99selinux"
		$s5 = "cp %s %s -rf"
		$s6 = "dnsAmp"
		$s7 = "dosset.dtdb"
		$s8 = "DoubleDoMain1"
		$s9 = "DoubleDoMain2"
		$s10 = "/etc/init.d/pktmake"
		$s11 = "chmod 777 /etc/init.d/pktmake"
		$s12 = "ln  -s  -f  /etc/init.d/pktmake  /etc/rc2.d/S99pktmake"
		$s13 = "ln  -s  -f  /etc/init.d/pktmake  /etc/rc.d/rc2.d/S99pktmake"

	condition:
		//all of them
($s0 and $s1) or ($s2 and $s3 and $s4 and $s5) or ($s6 and $s7 and $s8 and $s9) or ($s10 and $s11 and $s12 and $s13)
}
