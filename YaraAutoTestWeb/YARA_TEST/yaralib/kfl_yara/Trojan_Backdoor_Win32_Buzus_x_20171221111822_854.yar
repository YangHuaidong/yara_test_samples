rule Trojan_Backdoor_Win32_Buzus_x_20171221111822_854 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Buzus.x"
		threattype = "BackDoor"
		family = "Buzus"
		hacker = "None"
		refer = "142c51fb34eac32742baa4fba6d695f7"
		description = "None"
		comment = "None"
		author = "xc"
		date = "2017-09-30"
	strings:
		$s0 = "oivrip762hpp"
		$s1 = "lviehGsrxi"
		$s2 = "http://www.crypter.com"
		$s3 = "WXEXMG"
		$s4 = "PsehWxvmrkE"
		$s5 = "ywiv762hpp"

	condition:
		4 of them
}
