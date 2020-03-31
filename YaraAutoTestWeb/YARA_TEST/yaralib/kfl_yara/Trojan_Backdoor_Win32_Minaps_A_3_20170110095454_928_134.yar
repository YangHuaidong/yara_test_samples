rule Trojan_Backdoor_Win32_Minaps_A_3_20170110095454_928_134 
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
		$s0 = { 71 30 6e 63 39 77 38 65 64 61 6f 69 75 6b 32 6d 7a 72 66 79 33 78 74 31 70 35 6c 73 36 37 67 34 62 76 68 6a }
		$s1 = "MiniAsp.pdb" nocase wide ascii

	condition:
		any of them
}
