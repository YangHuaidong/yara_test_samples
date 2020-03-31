rule Trojan_Backdoor_Win32_Hupigon_23v1_20161213095119_917_109 
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
		$s1 = "D065937B3EFF588ACE49FB7124009C99"

	condition:
		all of them
}
