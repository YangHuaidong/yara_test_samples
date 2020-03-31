rule Trojan_RAT_Win32_Bitter_a_20161213095214_1073_597 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Bitter.a"
		threattype = "rat"
		family = "Bitter"
		hacker = "None"
		refer = "b89e1cb807779f405c5b7cd122880e2e"
		description = "None"
		comment = "None"
		author = "sxy"
		date = "2016-11-16"
	strings:
		$s0 = "BITTER1234"
		$s1 = "D:\\MyWork\\VisualSudio\\mwow\\Debug\\mwow.pdb"

	condition:
		1 of them
}
