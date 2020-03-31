rule Trojan_DDoS_Linux_MrBlack_A_20171221111925_910 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.MrBlack.A"
		threattype = "DDOS"
		family = "MrBlack"
		hacker = "None"
		refer = "4c40639b6604c18e79fbe6e02d8ecd1e,4e98c08168a436cbbf73361c260a64a2,a5cfefb13ea8dd17f6724bec05d9b3a5"
		description = "None"
		comment = "None"
		author = "LiuGuangZhu"
		date = "2017-08-20"
	strings:
		$s0 = "Mr.Black"	//"\x4D\x72\x2E\x42\x6C\x61\x63\x6B"
		$s1 = "VERSONEX:%s|%d|%d|%s"
		$s2 = "eth0:%Lu %Lu %Lu %Lu %Lu %Lu %Lu %Lu %Lu"
		$s3 = "INFO:%d|%d"
		$s4 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"
		$s5 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"

	condition:
		//all of them
$s0 and (($s1 and $s2 and $s3) or ($s2 and $s3) or ($s4 and $s5))
}
