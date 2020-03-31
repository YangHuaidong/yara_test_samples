rule Trojan_Linux_Mirai_C_20170407172749_1057_559 
{
	meta:
		judge = "black"
		threatname = "Trojan/Linux.Mirai.C"
		threattype = "DDOS"
		family = "Mirai"
		hacker = "None"
		refer = "2ffc63bdbb3158c15a80286ea33382aa,5fced6cd62544367b9c571c6257dfe68,7938efbc2ee2ea3501cf8a34ed30e030,bc87838723376af50484771e52ac20d3,f50ce9abf685eddb5fa31ab276f2f2c5"
		description = "None"
		comment = "None"
		author = "LGZ"
		date = "2017-03-13"
	strings:
		$s0 = "qCDCPK"
		$s1 = "CRRNKACVKML"
		$s2 = "AMMIKG"
		$s3 = "aMLLGAVKML"
		$s4 = "cAAGRV"
		$s5 = "assword"
		$s6 = "pgrmpv"
		$s7 = "CRRNGV"
		$s8 = "gLEKLG"
		$s9 = "nCLEWCEG"
		$s10 = "NMACVKML"
		$s11 = "AMLVGLV"
		$s12 = "NGLEVJ"
		$s13 = "VPCLQDGP"
		$s14 = "ANMWFDNCPG"

	condition:
		8 of them
}
