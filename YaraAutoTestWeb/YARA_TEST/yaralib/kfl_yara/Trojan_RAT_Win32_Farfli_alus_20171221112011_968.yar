rule Trojan_RAT_Win32_Farfli_alus_20171221112011_968 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Farfli.alus"
		threattype = "rat"
		family = "Farfli"
		hacker = "None"
		refer = "82f7dc101bff8ce6c9e4c6aed07a5dd2"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-10-10"
	strings:
		$s0 = { 4e 00 65 00 74 00 2e 00 53 00 6f 00 66 00 74 00 20 00 53 00 74 00 75 00 64 00 69 00 6f 00 }
		$s1 = { 61 00 64 00 62 00 72 00 6f 00 77 00 73 00 65 00 72 00 2e 00 45 00 58 00 45 }
		$s2 = "rngzcz"
		$s3 = "nccFED"
		$s4 = "RmcNMr"
		$s5 = "SRQccccPWVU"
		$s6 = { 5a bd 55 9b 4b 4a 68 c3 36 de 49 48 a2 ea 52 6d }

	condition:
		5 of them
}
