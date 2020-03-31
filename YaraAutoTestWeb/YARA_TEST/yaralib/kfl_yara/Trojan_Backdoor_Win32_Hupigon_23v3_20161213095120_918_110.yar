rule Trojan_Backdoor_Win32_Hupigon_23v3_20161213095120_918_110 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Hupigon.23v3"
		threattype = "rat"
		family = "Hupigon"
		hacker = "None"
		refer = "229095614004bdaa3eb52895cada236d,65db03eb23ddd28bdbe7e177a9653dfc"
		description = "None"
		comment = "None"
		author = "djw"
		date = "2016-09-01"
	strings:
		$s0 = "Delphi"
		$s1 = "C351D699FCDC1DD91A2F343182A65927"

	condition:
		all of them
}
