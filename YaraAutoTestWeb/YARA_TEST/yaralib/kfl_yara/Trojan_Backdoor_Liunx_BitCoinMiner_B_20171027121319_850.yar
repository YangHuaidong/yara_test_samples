rule Trojan_Backdoor_Liunx_BitCoinMiner_B_20171027121319_850 
{
	meta:
		judge = "black"
		threatname = "Trojan[BackDoor]/Linux.BitCoinMiner.B"
		threattype = "BackDoor"
		family = "BitCoinMiner"
		hacker = "None"
		refer = "be54a4a931109795b4e526cc54247021"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-09-25"
	strings:
		$s0 = { 7b 22 6d 65 74 68 6f 64 22 3a 22 73 75 62 6d 69 74 22 2c 22 70 61 72 61 6d 73 22 3a 7b 22 69 64 22 3a 22 25 73 22 2c 22 6a 6f 62 5f 69 64 22 3a 22 25 73 22 2c 22 6e 6f 6e 63 65 22 3a 22 25 73 22 2c 22 72 65 73 75 6c 74 22 3a 22 25 73 22 7d 2c 22 69 64 22 3a 31 7d }
		$s1 = "cryptonight"
		$s2 = "ftp://%s:%s@%s"
		$s3 = "%s://%s%s%s:%hu%s%s%s"
		$s4 = { 68 74 74 70 73 3a 2f 2f 63 75 72 6c 2e 68 61 78 78 2e 73 65 }
		$s5 = "/etc/resolv.conf"
		$s6 = "/proc/%d/exe"
		$s7 = "cat /etc/crontab"

	condition:
		all of them
}
