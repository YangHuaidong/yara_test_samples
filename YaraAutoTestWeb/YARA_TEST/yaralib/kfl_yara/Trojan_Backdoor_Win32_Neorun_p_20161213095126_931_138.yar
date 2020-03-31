rule Trojan_Backdoor_Win32_Neorun_p_20161213095126_931_138 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Neorun.p"
		threattype = "rat"
		family = "Neorun"
		hacker = "None"
		refer = "d1481d43e443775f426e5dc203ab0b64"
		description = "Mirage Identifying Strings"
		comment = "None"
		author = "Seth Hardy"
		date = "2014-06-25"
	strings:
		$s0 = "Neo,welcome to the desert of real." wide ascii
		$s1 = "/result?hl=en&id=%s"

	condition:
		any of them
}
