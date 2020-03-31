rule Trojan_Backdoor_Win32_Ecltys_A_1_20170110095447_905_60 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Ecltys.A"
		threattype = "rat"
		family = "Ecltys"
		hacker = "None"
		refer = "582207d1f939f80bacc36a7790f40dc8"
		description = "CommentCrew-threat-apt1,EclipseSunCloudRAT"
		comment = "None"
		author = "AlienVault Labs"
		date = "2016-12-27"
	strings:
		$s0 = "Eclipse_A" wide ascii
		$s1 = "\\PJTS\\" wide ascii
		$s2 = "Eclipse_Client_B.pdb" wide ascii
		$s3 = "XiaoME" wide ascii
		$s4 = "SunCloud-Code" wide ascii
		$s5 = "/uc_server/data/forum.asp" wide ascii

	condition:
		any of them
}
