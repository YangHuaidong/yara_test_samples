rule Trojan_RAT_Win32_Farfli_alus_810
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Farfli.alus"
		threattype = "RAT"
		family = "Farfli"
		hacker = "None"
		refer = "82f7dc101bff8ce6c9e4c6aed07a5dd2"
		author = "HuangYY"
		comment = "None"
		date = "2017-10-10"
		description = "None"

	strings:		
		$s0 = {4E 00 65 00 74 00 2E 00 53 00 6F 00 66 00 74 00 20 00 53 00 74 00 75 00 64 00 69 00 6F 00}
		$s1 = {61 00 64 00 62 00 72 00 6F 00 77 00 73 00 65 00 72 00 2E 00 45 00 58 00 45}
		$s2 = "rngzcz"
		$s3 = "nccFED"
		$s4 = "RmcNMr"
		$s5 = "SRQccccPWVU"
		$s6 = {5A BD 55 9B 4B 4A 68 C3 36 DE 49 48 A2 EA 52 6D}
	condition:
		5 of them
}