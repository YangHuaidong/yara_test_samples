rule Trojan_RAT_Win32_Scar_20161213095247_1101_631 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Scar"
		threattype = "rat"
		family = "Scar"
		hacker = "None"
		refer = "32291E232247E9004E520D0E638F565D"
		description = "rat zhoumingyang"
		comment = "None"
		author = "wgh"
		date = "2016-11-23"
	strings:
		$s0 = "clddosid="
		$s1 = "Tmp.ini"
		$s2 = "Ati External Event Ut"
		$s3 = "Pass360"
		$s4 = "hytyju"
		$s5 = "zhaomingyang"

	condition:
		4 of them
}
