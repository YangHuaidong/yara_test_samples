rule Trojan_DDoS_Win32_Huigezi_20170705104800_1009_301 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Huigezi"
		threattype = "DDOS"
		family = "Huigezi"
		hacker = "None"
		refer = "c121edeb6502f1736ca418c004980369"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-06-27"
	strings:
		$s0 = "get_Keys"
		$s1 = "http://tempuri.org/"
		$s2 = "http://dota.hgzvip.net/"
		$s3 = "http://crls1.wosign.com/"

	condition:
		all of them
}
