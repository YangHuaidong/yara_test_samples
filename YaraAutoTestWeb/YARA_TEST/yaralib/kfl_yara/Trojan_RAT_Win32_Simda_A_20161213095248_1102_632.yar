rule Trojan_RAT_Win32_Simda_A_20161213095248_1102_632 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Simda.A"
		threattype = "rat"
		family = "Simda"
		hacker = "None"
		refer = "a0e816d37a29fffcbe5da107f26df4f2"
		description = "Simda  Backdoor"
		comment = "None"
		author = "dengcong"
		date = "2016-11-22"
	strings:
		$a1 = "keylog.txt"
		$a2 = "pass.log"
		$a3 = "links.log"
		$a4 = "IBANK"
		$a5 = "AGAVA"
		$a6 = "ALPHA"
		$a7 = "COLV"
		$a8 = "CRAIF"
		$a9 = "FAKTURA"
		$a10 = "INIST"
		$a11 = "INTER-PRO"
		$a12 = "RAIFF RSTYLE VEFK"
		$a13 = "SbieDll.dll"

	condition:
		5 of them
}
