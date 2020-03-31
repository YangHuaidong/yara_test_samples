rule Trojan_DDoS_Win32_Nitol_C_20171221111946_933 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Nitol.C"
		threattype = "DDOS"
		family = "Nitol"
		hacker = "None"
		refer = "a48478dd55d8b099409bb829fb2b282f"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-09-21"
	strings:
		$s0 = "2xtwnl3Ck"
		$s1 = "www.baidu.com"
		$s3 = "txHtnHtaHtTHtG"
		$s4 = { 68 00 65 00 6c 00 6c 00 6f 00 2e 00 65 00 78 00 65 }
		$s5 = { 59 00 61 00 67 00 75 00 20 00 4d 00 75 00 73 00 69 00 63 00 }
		$s6 = { 4d 00 53 00 20 00 53 00 61 00 6e 00 73 00 20 00 53 00 65 00 72 00 69 00 66 00 }

	condition:
		all of them
}
