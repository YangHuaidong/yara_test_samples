rule Trojan_Linux_Mirai_Eb_20170324123754_1058_560 
{
	meta:
		judge = "black"
		threatname = "Trojan/Linux.Mirai.Eb"
		threattype = "DDOS"
		family = "Mirai"
		hacker = "None"
		refer = "2ffc63bdbb3158c15a80286ea33382aa,5fced6cd62544367b9c571c6257dfe68,7938efbc2ee2ea3501cf8a34ed30e030,bc87838723376af50484771e52ac20d3,f50ce9abf685eddb5fa31ab276f2f2c5"
		description = "None"
		comment = "None"
		author = "LGZ"
		date = "2017-03-13"
	strings:
		$s0 = "ODMBKIAI"
		$s1 = "MBXDCBU"
		$s2 = "NEXBMAE"
		$s3 = "HMIACB"
		$s4 = "HINEMB"
		$s5 = "JEBMBOI"
		$s6 = "EOEBKM"
		$s7 = "FCDBBU"
		$s8 = "BCNCHU"
		$s9 = "FYMBXIOD"
		$s10 = "XCAOMX"
		$s11 = "assword"

	condition:
		6 of them
}
