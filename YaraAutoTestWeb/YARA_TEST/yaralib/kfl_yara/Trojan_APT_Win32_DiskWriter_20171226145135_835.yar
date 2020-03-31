rule Trojan_APT_Win32_DiskWriter_20171226145135_835 
{
	meta:
		judge = "black"
		threatname = "Trojan[APT]/Win32.DiskWriter"
		threattype = "APT"
		family = "DiskWriter"
		hacker = "None"
		refer = "3e8a4d654d5baa99f8913d8e2bd8a184"
		description = "None"
		comment = "None"
		author = "xc"
		date = "2017-12-13"
	strings:
		$s0 = "C:\\ProgramData\\Log.txt" nocase wide ascii
		$s1 = "asdhgasdasdwqe" nocase wide ascii
		$s2 = "AaCcdDeFfGhiKLlMmnNoOpPrRsSTtUuVvwWxyZz32" nocase wide ascii
		$s3 = "Apwg0" nocase wide ascii
		$s4 = "\\\\.\\PhysicalDrive" nocase wide ascii

	condition:
		3 of them
}
