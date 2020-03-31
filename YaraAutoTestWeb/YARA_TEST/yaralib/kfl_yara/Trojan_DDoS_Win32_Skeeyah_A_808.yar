rule Trojan_DDoS_Win32_Skeeyah_A_808
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Skeeyah.A"
		threattype = "DDoS"
		family = "Skeeyah"
		hacker = "None"
		refer = "10e54e97d582c36260499272bcc6494d"
		author = "HuangYY"
		comment = "None"
		date = "2017-11-02"
		description = "None"

	strings:		
		$s0 = {63 00 6D 00 64 00 2E 00 65 00 78 00 65 00 20 00}
		$s1 = {5F 43 6F 72 45 78 65 4D 61 69 6E 00 6D 73 63 6F 72 65 65 2E 64 6C 6C 00}
		$s2 = {42 00 43 00 5F 00 43 00 6C 00 69 00 65 00 6E 00 74 00}
		$s3 = {63 00 6D 00 64 00 2E 00 65 00 78 00 65 00 20 00 2F 00 6B 00 20 00 70 00 69 00 6E 00 67 00 20 00 30 00 20 00 26 00 20 00 64 00 65 00 6C 00 20 00}
		$s4 = {52 00 65 00 6D 00 6F 00 76 00 65 00}
		$s5 = {44 00 6F 00 77 00 6E 00 6C 00 6F 00 61 00 64 00 44 00 61 00 74 00 61 00}
		$s6 = {46 00 69 00 6C 00 65 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00}
		
	condition:
		5 of them
}