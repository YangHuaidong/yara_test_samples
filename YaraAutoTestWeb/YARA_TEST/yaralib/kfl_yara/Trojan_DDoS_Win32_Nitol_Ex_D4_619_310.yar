rule Trojan_DDoS_Win32_Nitol_Ex_D4_619_310
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Nitol"
		threattype = "DDoS"
		family = "Nitol"
		hacker = "None"
		refer = "39aa2640e8adb553836f4ba4f8dee0a4"
		author = "lizhenling"
		comment = "None"
		date = "2018-08-23"
		description = "None"

	strings:		
		$s0 = "AV__non_rtti_object@std@@"
		$s1 = "NtFNt#NuV"
		$s2 = "5e5j5R5Z5_5M5"
		$s3 = "5e5l5]5D5H5L5"
		$s4 = "PPPPPPPPPPPPPPa"
		$s5 = "9r9w9a9k9P9Z9D9I9"
		
	condition:
		5 of them
}