rule Trojan_Win32_BitCoinMiner_B_732
{
	meta:
		judge = "black"
		threatname = "Trojan[BackDoor]/Win32.BitCoinMiner.B"
		threattype = "BackDoor"
		family = "BitCoinMiner"
		hacker = "None"
		refer = "d0d9a22c8ca3b8b5c7e2e414af58c8c7"
		author = "HuangYY"
		comment = "None"
		date = "2017-09-06"
		description = "None"

	strings:		
		$s0 = "sfxrar.pdb"
		$s1 = "xderver.reg"
		$s2 = "taskhost.exe"
		$s3 = "chrome.exe.exe"
		$s4 = "CRTProvider"
	condition:
		all of them
}