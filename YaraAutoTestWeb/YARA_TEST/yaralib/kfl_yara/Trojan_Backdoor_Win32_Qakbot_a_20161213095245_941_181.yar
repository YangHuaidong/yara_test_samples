rule Trojan_Backdoor_Win32_Qakbot_a_20161213095245_941_181 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Qakbot.a"
		threattype = "rat"
		family = "Qakbot"
		hacker = "None"
		refer = "dfd6d94b0e753e4c6f7070e7c2ead229"
		description = "NionSpy"
		comment = "None"
		author = "None"
		date = "2016-06-23"
	strings:
		$s0 = "aCfG92KXpcSo4Y94BnUrFmnNk27EhW6CqP5EnT"
		$s1 = "ad6af8bd5835d19cc7fdc4c62fdf02a1"
		$s2 = "%s?cstorage=shell&comp=%s"

	condition:
		1 of them
}
