rule Trojan_RAT_Win32_Virut_cecp_20170918171506_995 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Virut.cecp"
		threattype = "rat"
		family = "Virut"
		hacker = "None"
		refer = "06085536e3c529261d71413f07bd2d24"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-09-13"
	strings:
		$s0 = "C:\\program Files\\Crack\\" nocase wide ascii
		$s1 = "Kother599" nocase wide ascii
		$s2 = "LtkC3" nocase wide ascii

	condition:
		all of them
}
