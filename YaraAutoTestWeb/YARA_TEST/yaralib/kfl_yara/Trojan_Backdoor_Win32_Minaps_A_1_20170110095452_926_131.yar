rule Trojan_Backdoor_Win32_Minaps_A_1_20170110095452_926_131 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Minaps.A"
		threattype = "rat"
		family = "Minaps"
		hacker = "None"
		refer = "6b14351ba454bcbfccbaf213f83a1282"
		description = "CommentCrew-threat-apt1"
		comment = "None"
		author = "AlienVault Labs"
		date = "2016-12-27"
	strings:
		$s0 = "MiniAsp.pdb" wide ascii
		$s1 = "device_t=" wide ascii

	condition:
		all of them
}
