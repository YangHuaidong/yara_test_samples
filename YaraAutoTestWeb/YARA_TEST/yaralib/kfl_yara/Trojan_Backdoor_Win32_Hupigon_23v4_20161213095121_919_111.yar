rule Trojan_Backdoor_Win32_Hupigon_23v4_20161213095121_919_111 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Hupigon.23v4"
		threattype = "rat"
		family = "Hupigon"
		hacker = "None"
		refer = "229095614004bdaa3eb52895cada236d"
		description = "None"
		comment = "None"
		author = "djw"
		date = "2016-09-01"
	strings:
		$s0 = "Delphi"
		$s1 = "VERONETWO20070309"

	condition:
		all of them
}
