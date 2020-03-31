rule Trojan_DDoS_Win32_CoinMiner_20170918171445_921 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.CoinMiner"
		threattype = "DDOS"
		family = "CoinMiner"
		hacker = "None"
		refer = "d0d9a22c8ca3b8b5c7e2e414af58c8c7"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-09-06"
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
