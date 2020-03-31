rule Trojan_Backdoor_Linux_BitCoinMiner_E_730
{
	meta:
		judge = "black"
		threatname = "Trojan[BackDoor]/Linux.BitCoinMiner.E"
		threattype = "BackDoor"
		family = "BitCoinMiner"
		hacker = "None"
		refer = "b245362aa364f94496380cfd2f002493"
		author = "HuangYY"
		comment = "None"
		date = "2017-09-25"
		description = "None"

	strings:		
		$s0 = "N5boost6detail1"
		$s1 = "impl_pINS_3log12v2s"
		$s2 = "posix4coreEEE"
		$s3 = "poolIwEEE11delete"
		$s4 = "N5boost3log12v2s"
		$s5 = "implISsEE"
		$s6 = "traitsIwESaIw"
	condition:
		5 of them
}