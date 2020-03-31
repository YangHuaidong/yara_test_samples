rule Trojan_Backdoor_Win32_EggDrop_15_1025
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.EggDrop.15"
		threattype = "Backdoor"
		family = "EggDrop"
		hacker = "None"
		refer = "91aed3b7d0a0fd8ba3da3b07e4294f0b"
		comment = "None"
		description = "Disclosed hacktool set (old stuff) - file InjectT.exe"
		author = "Florian Roth"
		date = "23.11.14"
		
	strings:
		$s0 = "%s -Install                          -->To Install The Service" fullword ascii
		$s1 = "Explorer.exe" fullword ascii
		$s2 = "%s -Start                            -->To Start The Service" fullword ascii
		$s3 = "%s -Stop                             -->To Stop The Service" fullword ascii
		$s4 = "The Port Is Out Of Range" fullword ascii
		$s7 = "Fail To Set The Port" fullword ascii
		$s11 = "\\psapi.dll" fullword ascii
		$s20 = "TInject.Dll" fullword ascii

		$x1 = "Software\\Microsoft\\Internet Explorer\\WinEggDropShell" fullword ascii
		$x2 = "injectt.exe" fullword ascii
	condition:
		( 1 of ($x*) ) and ( 3 of ($s*) )
}