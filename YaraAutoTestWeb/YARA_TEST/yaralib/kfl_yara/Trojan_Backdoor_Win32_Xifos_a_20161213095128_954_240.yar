rule Trojan_Backdoor_Win32_Xifos_a_20161213095128_954_240 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Xifos.a"
		threattype = "rat"
		family = "Xifos"
		hacker = "None"
		refer = "a4ad7335aa391519cc5fc9140f2562f2"
		description = "CommentCrew-threat-apt1"
		comment = "None"
		author = "AlienVault Labs"
		date = "2016-12-09"
	strings:
		$s0 = "thequickbrownfxjmpsvalzydg" wide ascii

	condition:
		all of them
}
