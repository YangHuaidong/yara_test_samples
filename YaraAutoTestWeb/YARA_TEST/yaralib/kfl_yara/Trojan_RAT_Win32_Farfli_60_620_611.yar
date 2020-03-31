rule Trojan_RAT_Win32_Farfli_60_620_611
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Farfli"
		threattype = "RAT"
		family = "Farfli"
		hacker = "None"
		refer = "ebc19552aed0715c88907c9f67715920"
		author = "lizhenling"
		comment = "None"
		date = "2018-08-16"
		description = "None"

	strings:		
		$s0 = "/utput$"
		$s1 = ".*Quy/"
		$s2 = "ForShare"
		$s3 = "RichGy"
		$s4 = "Shellex"
		$s5 = "strupr"
		$s6 = "Di%4k$"
		$s7 = "tiudennpm"
		
	condition:
		5 of them
}