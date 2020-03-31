rule Trojan_DDoS_Linux_Mirai_Demon1_1099
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Mirai.Demon1"
		threattype = "DDoS"
		family = "Mirai"
		hacker = "None"
		refer = "0b000230723338852b1dafec94745d71"
		author = "Luoxuan"
		comment = "None"
		date = "2019-04-23"
		description = "None"

	strings:
		$s0 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS"
		$s1 = "\x1B[1;31mDemon\x1B[1;37m[\x1B[1;31mV5.0\x1B[1;37m]\x1B[1;31m-->\x1B[1;37m[\x1B[0;36m%s\x1B[1;37m]\x1B[1;31m-->\x1B[1;37m[\x1B[0;36m%s\x1B[1;37m]\x1B[1;31m-->\x1B[1;37m[\x1B[0;36m%s\x1B[1;37m]\x1B[1;31m-->\x1B[1;37m[\x1B[0;36m%s\x1B[1;37m]"
		$s2 = "/etc/resolv.conf"
		$s3 = "/etc/config/resolv.conf"
		$s4 = "/etc/config/hosts"
	condition:
		all of them
}