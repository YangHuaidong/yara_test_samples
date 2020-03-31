rule Trojan_DDoS_Win32_Nitol_C_798
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Nitol.C"
		threattype = "DDoS"
		family = "Nitol"
		hacker = "None"
		refer = "a48478dd55d8b099409bb829fb2b282f"
		author = "HuangYY"
		comment = "None"
		date = "2017-09-21"
		description = "None"

	strings:		
		$s0 = "2xtwnl3Ck"
		$s1 = "www.baidu.com"
		$s3 = "txHtnHtaHtTHtG"
		$s4 = {68 00 65 00 6C 00 6C 00 6F 00 2E 00 65 00 78 00 65}
		$s5 = {59 00 61 00 67 00 75 00 20 00 4D 00 75 00 73 00 69 00 63 00}
		$s6 = {4D 00 53 00 20 00 53 00 61 00 6E 00 73 00 20 00 53 00 65 00 72 00 69 00 66 00}
	condition:
		all of them
}