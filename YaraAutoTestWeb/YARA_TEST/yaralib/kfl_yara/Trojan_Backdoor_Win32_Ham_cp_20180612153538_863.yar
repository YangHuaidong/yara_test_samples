rule Trojan_Backdoor_Win32_Ham_cp_20180612153538_863 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Ham.cp"
		threattype = "BackDoor"
		family = "Ham"
		hacker = "None"
		refer = "https://github.com/CylanceSPEAR/IOCs/blob/master/snake.wine.yar,https://threatvector.cylance.com/en_us/home/the-deception-project-a-new-japanese-centric-threat.html"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2018-05-30"
	strings:
		$s0 = { 8d 14 3e 8b 7d fc 8a 0c 11 32 0c 38 40 8b 7d 10 88 0a 8b 4d 08 3b c3 }
		$s1 = { 8d 0c 1f 8b 5d f8 8a 04 08 32 04 1e 46 8b 5d 10 88 01 8b 45 08 3b f2 }

	condition:
		any of them
}
