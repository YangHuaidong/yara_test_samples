rule Trojan_DDoS_Linux_Dofloo_A_20171221111858_892 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Dofloo.A"
		threattype = "DDOS"
		family = "Dofloo"
		hacker = "None"
		refer = "471d245496898cf3d39307da37a4fe71,8933a115eeb4348252a8b79b2d414cda,7b5cac102f9ac57690bc1c1c6a5a66ff,c17ac87d4461506d98883164fb3e79c3,40863476960fc347c19a1df7bdd91894,4de213e497cac99b7217400c9def56ee,72a0b5dc44320829019a2435f4ef3ad6"
		description = "None"
		comment = "None"
		author = "LiuGuangzhu"
		date = "2017-09-15"
	strings:
		$s0 = "VERSONEX:Linux-%s|%d|%d MHz|%dMB|%dMB|%s"
		$s1 = "VERSONEX:Linux-%s-arm|%d|%d MHz|%dMB|%dMB|%s"
		$s2 = "VERSONEX:Linux-%s|%d|%d|%dMB|%s|%s"
		$s3 = "VERSONEX:%s|%d|%d MHz|%dMB|%dMB|%s"
		$s4 = "Hacker"
		$s5 = "0.0%d Mbps"
		$s6 = "INFO:%d%%|%s Mbps"
		$s7 = "sed -i -e '/%s/d' /etc/rc.local"

	condition:
		($s0 or $s1 or $s2 or $s3) and $s4 and ($s5 or $s6 or $s7)
}
