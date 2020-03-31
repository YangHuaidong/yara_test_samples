rule Trojan_DDoS_Win32_Skeeyah_A_20171221112002_950 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Skeeyah.A"
		threattype = "DDOS"
		family = "Skeeyah"
		hacker = "None"
		refer = "10e54e97d582c36260499272bcc6494d"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-11-02"
	strings:
		$s0 = { 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 }
		$s1 = { 5f 43 6f 72 45 78 65 4d 61 69 6e 00 6d 73 63 6f 72 65 65 2e 64 6c 6c 00 }
		$s2 = { 42 00 43 00 5f 00 43 00 6c 00 69 00 65 00 6e 00 74 00 }
		$s3 = { 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 6b 00 20 00 70 00 69 00 6e 00 67 00 20 00 30 00 20 00 26 00 20 00 64 00 65 00 6c 00 20 00 }
		$s4 = { 52 00 65 00 6d 00 6f 00 76 00 65 00 }
		$s5 = { 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 44 00 61 00 74 00 61 00 }
		$s6 = { 46 00 69 00 6c 00 65 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 }

	condition:
		5 of them
}
