rule Trojan_DDoS_Win32_Nitol_J_801
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Nitol.J"
		threattype = "DDoS"
		family = "Nitol"
		hacker = "None"
		refer = "21ac2b7085eb7865a3d5c8603c9bb8e5"
		author = "HuangYY"
		comment = "None"
		date = "2017-09-06"
		description = "None"

	strings:		
		$s0 = "IEXPLORE.EXE"
		$s1 = {4D 00 53 00 20 00 53 00 61 00 6E 00 73 00 20 00 53 00 65 00 72 00 69 00 66}
		$s2 = {48 00 65 00 6C 00 6C 00 6F 00 20 00 41 00 64 00 6D 00 69 00 6E}
		$s3 = {48 00 65 00 6C 00 6C 00 6F 00 20 00 41 00 64 00 6D 00 69 00 6E}
		$s4 = "ftsWordBreak"
		$s5 = "LpkEditControl"
		$s6 = "TCPConnectFloodThread.target = %s"
		$s7 = "CCAttack.target"
		$s8 = "lpk.attack"
	condition:
		all of them
}