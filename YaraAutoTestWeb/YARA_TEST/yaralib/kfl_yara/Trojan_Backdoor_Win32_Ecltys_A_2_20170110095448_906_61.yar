rule Trojan_Backdoor_Win32_Ecltys_A_2_20170110095448_906_61 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Ecltys.A"
		threattype = "rat"
		family = "Ecltys"
		hacker = "None"
		refer = "582207d1f939f80bacc36a7790f40dc8"
		description = "CommentCrew-threat-apt1"
		comment = "None"
		author = "AlienVault Labs"
		date = "2016-12-27"
	strings:
		$0 = "\\pipe\\ssnp" wide ascii
		$1 = "toobu.ini" wide ascii
		$2 = "Serverfile is not bigger than Clientfile" wide ascii
		$3 = "URL download success" wide ascii

	condition:
		3 of them
}
