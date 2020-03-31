rule Trojan_HackTool_Win32_GetIn_a_1030 
{
	meta:
		judge = "black"
		threatname = "Trojan[HackTool]/Win32.GetIn.a"
		threattype = "HackTool"
		family = "GetIn"
		hacker = "None"
		refer = "eb9e5b2ee0ca6dcede36ae0eb27bdda2"
		comment = "None"
		description = "Disclosed hacktool set (old stuff) - file letmein.exe"
		author = "Florian Roth"
		date = "23.11.14"
		
	strings:
		$s1 = "Error get globalgroup memebers: NERR_InvalidComputer" fullword ascii
		$s6 = "Error get users from server!" fullword ascii
		$s7 = "get in nt by name and null" fullword ascii
		$s16 = "get something from nt, hold by killusa." fullword ascii
	condition:
		all of them
}