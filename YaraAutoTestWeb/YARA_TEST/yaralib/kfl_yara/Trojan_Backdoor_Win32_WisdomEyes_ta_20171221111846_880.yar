rule Trojan_Backdoor_Win32_WisdomEyes_ta_20171221111846_880 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.WisdomEyes.ta"
		threattype = "BackDoor"
		family = "WisdomEyes"
		hacker = "None"
		refer = "ece9914b00872ded8d7b24b5a09576f3"
		description = "None"
		comment = "None"
		author = "xc"
		date = "2017-11-03"
	strings:
		$s0 = "file:///" nocase wide ascii
		$s1 = "ta.Properties" nocase wide ascii
		$s2 = "ta.exe" nocase wide ascii

	condition:
		all of them
}
