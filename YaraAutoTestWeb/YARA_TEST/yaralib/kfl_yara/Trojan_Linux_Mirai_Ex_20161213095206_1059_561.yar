rule Trojan_Linux_Mirai_Ex_20161213095206_1059_561 
{
	meta:
		judge = "black"
		threatname = "Trojan/Linux.Mirai"
		threattype = "DDOS"
		family = "Mirai"
		hacker = "None"
		refer = "4528cdf22e2fc26362cd295176fa84d3,2f7f5eb37e1671e56d3518ea249dfbf5,84417c5f1819f7ac8b9051646f69b0e4"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2016-11-03"
	strings:
		$s0 = "HWCLVGAJ"
		$s1 = "FGDCWNV"
		$s2 = "ZOJFKRA"
		$s3 = "QWRRMPV"
		$s4 = "RCQQUMPF"
		$s5 = "QOACFOKL"
		$s6 = "cFOKLKQVPCVMP"
		$s7 = "assword"

	condition:
		6 of them
}
