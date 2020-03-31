rule Trojan_DDoS_Win32_Nitol_Ex_D4_173_309
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Nitol"
		threattype = "DDoS"
		family = "Nitol"
		hacker = "None"
		refer = "462bc57b9e1ee74f238e3cbb16238c7a"
		author = "lizhenling"
		comment = "None"
		date = "2018-07-13"
		description = "None"

	strings:		
		$s0 = "AV__non_rtti_object@std@@"
		$s1 = "NewTest"
		$s2 = "teHtFHt&Hu"
		$s3 = "AtIHt0Hu"
		$s4 = "VVVVVQRSSj"
		$s5 = "NtFNt#NuV"
		
	condition:
		all of them
}