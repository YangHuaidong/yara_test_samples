rule Trojan_Backdoor_Win32_Zxshell_a_20161213095251_961_252 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Zxshell.a"
		threattype = "rat"
		family = "Zxshell"
		hacker = "None"
		refer = "e32c07d47fc8ebecb40ee129026be1e7"
		description = "None"
		comment = "None"
		author = "ThreatConnect Intelligence Research Team"
		date = "2016-12-08"
	strings:
		$s0 = "\\Control\\zxplug" nocase wide ascii
		$s1 = "http://www.facebook.com/comment/update.exe" wide ascii
		$s2 = "Shared a shell to %s:%s Successfully" nocase wide ascii

	condition:
		any of them
}
