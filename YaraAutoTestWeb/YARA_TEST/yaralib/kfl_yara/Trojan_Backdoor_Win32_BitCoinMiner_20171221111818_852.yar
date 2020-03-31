rule Trojan_Backdoor_Win32_BitCoinMiner_20171221111818_852 
{
	meta:
		judge = "black"
		threatname = "Trojan[BackDoor]/Win32.BitCoinMiner"
		threattype = "BackDoor"
		family = "BitCoinMiner"
		hacker = "None"
		refer = "f2c9ff4b162a3be01688f0e26083bffb"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-09-29"
	strings:
		$s0 = "JSON decode failed:"
		$s1 = "jsonrpc"
		$s2 = "method"
		$s3 = "cryptonight"
		$s4 = "keepalive"
		$s5 = "login error code"
		$s6 = "duplicate job received, ignore"

	condition:
		5 of them
}
