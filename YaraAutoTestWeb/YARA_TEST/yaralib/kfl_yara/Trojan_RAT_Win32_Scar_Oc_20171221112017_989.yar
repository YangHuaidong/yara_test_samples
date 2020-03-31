rule Trojan_RAT_Win32_Scar_Oc_20171221112017_989 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Scar.Oc"
		threattype = "rat"
		family = "Scar"
		hacker = "None"
		refer = "11dd7da7faa0130dac2560930e90c8b1"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-09-28"
	strings:
		$s0 = "zc%C1" nocase wide ascii
		$s1 = "ZwQuerySystemInformation" nocase wide ascii
		$s2 = "brbconfig.tmp" nocase wide ascii
		$s3 = "YnJiYm90" nocase wide ascii

	condition:
		all of them
}
