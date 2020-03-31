rule Trojan_Backdoor_Win32_Duqu2_SamsungPrint_1084
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Duqu2.SamsungPrint"
		threattype = "ICS,Backdoor"
		family = "Duqu2"
		hacker = "None"
		refer = "acbf2d1f8a419528814b2efa9284ea8b"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-03-21"
		description = "https://github.com/Yara-Rules/rules/blob/master/malware/APT_Duqu2.yar"
    strings:
		$s0 = "Installer for printer drivers and applications" fullword wide /* PEStudio Blacklist: strings */
		$s1 = "msi4_32.dll" fullword wide
		$s2 = "HASHVAL" fullword wide
		$s3 = "SELECT `%s` FROM `%s` WHERE `%s`='CAData%i'" fullword wide
		$s4 = "ca.dll" fullword ascii
		$s5 = "Samsung Electronics Co., Ltd." fullword wide
	
    condition:
		uint16(0) == 0x5a4d and filesize < 82KB and all of them
}