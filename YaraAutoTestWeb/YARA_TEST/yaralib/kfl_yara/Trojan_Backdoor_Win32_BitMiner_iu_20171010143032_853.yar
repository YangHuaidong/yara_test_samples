rule Trojan_Backdoor_Win32_BitMiner_iu_20171010143032_853 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.BitMiner.iu"
		threattype = "BackDoor"
		family = "BitMiner"
		hacker = "None"
		refer = "010a7fa751f4a64c989eacabf58c8fbf"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-09-21"
	strings:
		$s0 = "donate.xmr-stak.net:3333" nocase wide ascii
		$s1 = "pool.minexmr.com:5555" nocase wide ascii

	condition:
		all of them
}
