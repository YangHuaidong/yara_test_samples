rule Trojan_DDoS_Win32_BitCoinMiner_B_20170918171444_919 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.BitCoinMiner.B"
		threattype = "DDOS"
		family = "BitCoinMiner"
		hacker = "None"
		refer = "d0d9a22c8ca3b8b5c7e2e414af58c8c7"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-09-06"
	strings:
		$s0 = "sfxrar.pdb"
		$s1 = "xderver.reg"
		$s2 = "taskhost.exe"
		$s3 = "chrome.exe.exe"
		$s4 = "CRTProvider"

	condition:
		all of them
}
