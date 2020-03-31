rule Trojan_Win32_CoinMiner_733
{
	meta:
		judge = "black"
		threatname = "Trojan[BackDoor]/Win32.CoinMiner"
		threattype = "BackDoor"
		family = "CoinMiner"
		hacker = "None"
		refer = "d0d9a22c8ca3b8b5c7e2e414af58c8c7"
		author = "HuangYY"
		comment = "None"
		date = "2017-09-06"
		description = "None"

	strings:		
		$s0 = "xmrig.pdb"
		$s1 = "copyTo %ls ok!"
		$s3 = "jsonrpc"
		$s4 = "method"
		$s5 = "params"
		$s6 = "stratum+tcp"
	condition:
		all of them
}