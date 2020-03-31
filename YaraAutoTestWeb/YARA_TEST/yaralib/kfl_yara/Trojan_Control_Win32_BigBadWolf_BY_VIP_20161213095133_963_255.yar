rule Trojan_Control_Win32_BigBadWolf_BY_VIP_20161213095133_963_255 
{
	meta:
		judge = "black"
		threatname = "Trojan[Control]/Win32.BigBadWolf.BY_VIP"
		threattype = "rat"
		family = "BigBadWolf"
		hacker = "Boyuan work station"
		refer = "d90491df8a77dffabf4c08b2e3444f03,b7ebfe70fdeea91903d0c7710ad07ae5,5A56746B32A9B364B2B1867150BDD06D"
		description = "None"
		comment = "None"
		author = "HYY"
		date = "2016-06-14"
	strings:
		$s0 = "Wsoqmc mkgiiqso"
		$s1 = "Xkidlr fnzadfat"
		$s2 = "Qjrlua iyavnlobynkudfhgay"
		$c0 = "1type_info"
		$c1 = "http://user.qzone.qq.com/"

	condition:
		($s0 and $s1 and $s2) or ($c0 and $c1 )
}
