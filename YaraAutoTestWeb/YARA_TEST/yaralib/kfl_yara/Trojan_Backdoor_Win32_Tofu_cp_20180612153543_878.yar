rule Trojan_Backdoor_Win32_Tofu_cp_20180612153543_878 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Tofu.cp"
		threattype = "BackDoor"
		family = "Tofu"
		hacker = "None"
		refer = "https://www.cylance.com/en_us/blog/the-deception-project-a-new-japanese-centric-threat.html,https://github.com/CylanceSPEAR/IOCs/blob/master/snake.wine.yar"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2018-05-30"
	strings:
		$s0 = "Cookies: Sym1.0" nocase wide ascii
		$s1 = "\\\\.\\pipe\\1[12345678]" nocase wide ascii
		$s2 = { 66 0f fc c1 0f 11 40 d0 0f 10 40 d0 66 0f ef c2 0f 11 40 d0 0f 10 40 e0 }

	condition:
		any of them
}
