rule Trojan_Ransomware_Win32_Tescrypt_rfn_20171221112010_963 
{
	meta:
		judge = "black"
		threatname = "Trojan[Ransomware]/Win32.Tescrypt.rfn"
		threattype = "BackDoor"
		family = "Tescrypt"
		hacker = "None"
		refer = "1b1af48fe1763db5e870208926beeb96"
		description = "None"
		comment = "None"
		author = "copy"
		date = "2017-10-18"
	strings:
		$s0 = "sEhLLl" nocase wide ascii
		$s1 = "r3lsDo" nocase wide ascii
		$s2 = "eLfPD0" nocase wide ascii
		$s3 = "tialn;" nocase wide ascii

	condition:
		all of them
}
