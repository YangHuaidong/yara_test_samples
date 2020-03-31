rule Trojan_Backdoor_Win32_Toga_3389_20170705104757_949_227 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Toga.3389"
		threattype = "BackDoor"
		family = "Toga"
		hacker = "none"
		refer = "c71414d4a732cd18fc3b6c80ed57a56c"
		description = "None"
		comment = "none"
		author = "xc"
		date = "2017-06-27"
	strings:
		$s0 = "3389"
		$s1 = "S.exe"
		$s2 = "DUB.exe"

	condition:
		all of them
}
