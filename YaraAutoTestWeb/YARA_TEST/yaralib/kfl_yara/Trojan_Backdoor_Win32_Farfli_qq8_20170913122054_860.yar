rule Trojan_Backdoor_Win32_Farfli_qq8_20170913122054_860 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Farfli.qq8"
		threattype = "BackDoor"
		family = "Farfli"
		hacker = "None"
		refer = "3200653E88D7EDBD06FC573BB5184357"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-08-31"
	strings:
		$s0 = "QQ841374296" nocase wide ascii
		$s1 = "3389" nocase wide ascii

	condition:
		all of them
}
