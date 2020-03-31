rule Trojan_DDoS_Linux_Mirai_B_20171221111921_909 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Mirai.B"
		threattype = "DDOS"
		family = "Mirai"
		hacker = "None"
		refer = "9e0db843ffbd4dbd072fc040e2846497,376c0404e748a4c84e566b13ed19c7b9,9486488dcd9981e0c82e10a67af088f8,71689b50f8a1556226dd273570c6de89,88e1aca4feb9e6b6743a678f374f8a3c,0bd3d6050c9d6abacfee8f9359c43f49,588e0e236bf79c27072cd1dd2698223b,747dbf7845ab9fa97ba23e68f95c7e42,6150ee744412568b292e4822cc089322,45a7a8469e5129e59942ae7478c6058b,e734286cd48ebc0b18fd7af7997947b6,76312ed3e50a9a0671ccf305f376767c,bd528146e493fb2d2eff8da5ac02be0e,a29986a0e7005ac224cbcafb0029d3cb,a8c8b9b12029f7cb76df00401a9cfd8b,a2fa3289fae94da29ae913d68cd8cdf0,c3b213451c04a911c8d9fdb9869a1185,6fc55febf7cae1b0e73e2c7f3e45ebc9,3a10e28e70c1b17af81cd89de3d36bdf,78163c45c6a26741edbbf5517a28401d"
		description = "None"
		comment = "None"
		author = "LiuGuangzhu"
		date = "2017-08-18"
	strings:
		$s0 = "/proc/net/tcp"
		$s1 = "/dev/watchdog"
		$s2 = "/dev/misc/watchdog"
		$s3 = "aMLLGAVKML"
		$s4 = "cAAGRV"
		$s5 = "CRRNKACVKML"
		$s6 = "qCDCPK"
		$s7 = "ANMWFDNCPG"
		$s8 = "VPCLQDGP"
		$s9 = "NGLEVJ"
		$s10 = "AMLVGLV"
		$s11 = "AMMIKG"
		$s12 = "NMACVKML"
		$s13 = "nCLEWCEG"

	condition:
		all of them
//$s0 and $s1 and $s2 and $s3 and $s4 and $s5 and $s6 and $s7 and $s8 and $s9 and $s10 and $s11 and $s12 and $s13
}
