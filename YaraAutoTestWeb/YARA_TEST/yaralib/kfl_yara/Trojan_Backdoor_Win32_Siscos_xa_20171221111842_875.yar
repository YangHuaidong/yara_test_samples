rule Trojan_Backdoor_Win32_Siscos_xa_20171221111842_875 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Siscos.xa"
		threattype = "BackDoor"
		family = "Siscos"
		hacker = "None"
		refer = "11c2d539b5a99c6df618f5be92bacfdb"
		description = "None"
		comment = "None"
		author = "xc"
		date = "2017-09-28"
	strings:
		$s0 = "WXEXMG"
		$s1 = "ywiv762hpp"
		$s2 = "Xlmw$mw$xli$XVMEP$zivwmsr2"

	condition:
		all of them
}
