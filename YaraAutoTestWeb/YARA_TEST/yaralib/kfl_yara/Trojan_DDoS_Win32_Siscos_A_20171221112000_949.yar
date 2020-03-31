rule Trojan_DDoS_Win32_Siscos_A_20171221112000_949 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Siscos.A"
		threattype = "DDOS"
		family = "Siscos"
		hacker = "None"
		refer = "86c87abf55035cb76e6779a101f78525"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-05-31"
	strings:
		$s0 = "tooRmetsyS"
		$s1 = "d2.%:d2.% d2.%-d2.%-d4%"
		$s2 = "yxorPnepO"
		$s3 = "yxorPmh"
		$s4 = " del /f/q \"%s\""
		$s5 = "yxorPesolC"
		$s6 = "yxorPesolC"

	condition:
		all of them
}
