rule Trojan_DDoS_Linux_Sotdas_A_785
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Sotdas.A"
		threattype = "DDoS"
		family = "Sotdas"
		hacker = "None"
		refer = "2b3119503ed32ef51e3bf9f5e3f5b633,099a476f30d594aef9e4fe93b9d6545b"
		author = "HuangYY"
		comment = "None"
		date = "2017-08-20"
		description = "None"
	strings:		
		$s0 = "Referer: %s%s%s"
		$s1 = "rm -f /boot/IptabLes ; rm -f /boot/.IptabLes"
		$s2 = "/proc/net/dev"
		$s3 = "/tmp/gconfd.bin"
		$s4 = "ln -s /etc/init.d/%s /etc/rc2.d/S77%s"
		$s5 = "ln -s /etc/init.d/%s /etc/rc3.d/S77%s"
		$s6 = "ln -s /etc/init.d/%s /etc/rc4.d/S77%s"
		$s7 = "ln -s /etc/init.d/%s /etc/rc5.d/S77%s"
		$s8 = "echo yes|cp -p %s %s"
		$s9 = "SYN@%s:%d"
		$s10 = "UDP@%s:%d"
		$s11 = "TCP@%s:%d#%s"
	condition:
		all of them
}