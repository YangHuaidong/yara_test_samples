rule Trojan_Backdoor_Win32_Hupigon_2007_20161213095118_921_113 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Hupigon.2007"
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
		$s1 = { d4 b6 b3 cc b4 f2 bf aa b3 c9 b9 a6 2e }

	condition:
		all of them
}
