rule Trojan_RAT_Win32_Symmi_busi_20170811104346_992 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Symmi.busi"
		threattype = "rat"
		family = "Symmi"
		hacker = "none"
		refer = "a68bc875b14270ea9cc2f61ffae1414f"
		description = "None"
		comment = "none"
		author = "xc"
		date = "2017-07-27"
	strings:
		$s0 = "del busi.exe"
		$s1 = "del busi.batMZ"
		$s2 = "manhack.txt"
		$s3 = "222.186.191.180"

	condition:
		all of them
}
