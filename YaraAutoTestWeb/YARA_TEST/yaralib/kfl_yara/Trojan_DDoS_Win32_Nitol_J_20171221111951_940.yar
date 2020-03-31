rule Trojan_DDoS_Win32_Nitol_J_20171221111951_940 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Nitol.J"
		threattype = "DDOS"
		family = "Nitol"
		hacker = "None"
		refer = "21ac2b7085eb7865a3d5c8603c9bb8e5"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-09-06"
	strings:
		$s0 = "IEXPLORE.EXE"
		$s1 = { 4d 00 53 00 20 00 53 00 61 00 6e 00 73 00 20 00 53 00 65 00 72 00 69 00 66 }
		$s2 = { 48 00 65 00 6c 00 6c 00 6f 00 20 00 41 00 64 00 6d 00 69 00 6e }
		$s3 = { 48 00 65 00 6c 00 6c 00 6f 00 20 00 41 00 64 00 6d 00 69 00 6e }
		$s4 = "ftsWordBreak"
		$s5 = "LpkEditControl"
		$s6 = "TCPConnectFloodThread.target = %s"
		$s7 = "CCAttack.target"
		$s8 = "lpk.attack"

	condition:
		all of them
}
