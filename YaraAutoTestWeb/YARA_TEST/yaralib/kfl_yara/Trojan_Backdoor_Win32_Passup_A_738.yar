rule Trojan_Backdoor_Win32_Passup_A_738
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Passup.A"
		threattype = "Backdoor"
		family = "Passup"
		hacker = "None"
		refer = "0fd79539a3295d884e738cfdb419e8bf"
		author = "HuangYY"
		comment = "None"
		date = "2017-11-02"
		description = "None"

	strings:		
		$s0 = {52 00 41 00 34 00 57 00 20 00 56 00 50 00 4E 00 2E 00 65 00 78 00 65 00}
		$s1 = {53 00 79 00 73 00 74 00 65 00 6D 00 2E 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 2E 00 43 00 72 00 79 00 70 00 74 00 6F 00 67 00 72 00 61 00 70 00 68 00 79}
		$s2 = {50 75 62 6C 69 63 4B 65 79 54 6F 6B 65 6E 3D}
		$s3 = "ziB6wmH4W66TIDh3hM"
		$s4 = "8Alp3YqnfE4zupfwt8"
		$s5 = "XzLUzDEBFjdpwsbYgB"
		$s6 = "wgHuSRaAQEkG3WoF"
	condition:
		5 of them
}