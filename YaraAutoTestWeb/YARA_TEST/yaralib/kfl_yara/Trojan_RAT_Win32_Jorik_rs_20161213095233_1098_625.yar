rule Trojan_RAT_Win32_Jorik_rs_20161213095233_1098_625 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Jorik.rs"
		threattype = "rat"
		family = "Jorik"
		hacker = "None"
		refer = "7A5DCE41E48013B9C1D2D1E445E761E3"
		description = "None"
		comment = "None"
		author = "felicity_chou"
		date = "2016-11-23"
	strings:
		$s0 = "&key=0x%.8x&o=%d&id=%s&vol=%s&id2=np:%d"
		$s1 = "kid=%.8x%s"

	condition:
		all of them
}
