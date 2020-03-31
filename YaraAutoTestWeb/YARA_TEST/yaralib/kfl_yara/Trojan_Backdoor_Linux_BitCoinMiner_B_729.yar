rule Trojan_Backdoor_Liunx_BitCoinMiner_B_729
{
	meta:
		judge = "black"
		threatname = "Trojan[BackDoor]/Linux.BitCoinMiner.B"
		threattype = "BackDoor"
		family = "BitCoinMiner"
		hacker = "None"
		refer = "be54a4a931109795b4e526cc54247021"
		author = "HuangYY"
		comment = "None"
		date = "2017-09-25"
		description = "None"

	strings:		
		$s0 = "Can not set SSL crypto engine as default"
		$s1 = "Failed to initialise SSL crypto engine"
		$s2 = "Problem with the SSL CA cert"
		$s3 = "Failed to shut down the SSL connection"
		$s4 = "The easy handle is already added to a multi handle"
		$s5 = "TRUE.FALSE.Server"
		$s6 = "default arg"
	condition:
		5 of them
}