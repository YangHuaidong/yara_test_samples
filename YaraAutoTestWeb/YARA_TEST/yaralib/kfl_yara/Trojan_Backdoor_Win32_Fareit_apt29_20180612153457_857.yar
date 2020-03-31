rule Trojan_Backdoor_Win32_Fareit_apt29_20180612153457_857 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Fareit.apt29"
		threattype = "BackDoor"
		family = "Fareit"
		hacker = "None"
		refer = "617ba99be8a7d0771628344d209e9d8a"
		description = "None"
		comment = "APT29"
		author = "Florian Roth-copy"
		date = "2018-06-05"
	strings:
		$s1 = "S:\\Lidstone\\renewing\\HA\\disable\\In.pdb" fullword ascii
		$s2 = "Repeat last find command)Replace specific text with different text" fullword wide
		$s3 = "l\\Processor(0)\\% Processor Time" fullword wide
		$s6 = "Self Process" fullword wide
		$s7 = "Default Process" fullword wide
		$s8 = "Star Polk.exe" fullword wide

	condition:
		( uint16(0) == 0x5a4d and filesize < 300KB and 4 of them )
}
