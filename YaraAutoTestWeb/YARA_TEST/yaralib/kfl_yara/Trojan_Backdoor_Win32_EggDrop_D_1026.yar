rule Trojan_Backdoor_Win32_EggDrop_D_1026
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.EggDrop.D"
		threattype = "Backdoor"
		family = "EggDrop"
		hacker = "None"
		refer = "f945de25e0eba3bdaf1455b3a62b9832"
		comment = "None"
		description = "Disclosed hacktool set (old stuff) - file EditServer.exe"
		author = "Florian Roth"
		date = "23.11.14"
		
	strings:
		$s0 = "%s Server.exe" fullword ascii
		$s1 = "Service Port: %s" fullword ascii
		$s2 = "The Port Must Been >0 & <65535" fullword ascii
		$s8 = "3--Set Server Port" fullword ascii
		$s9 = "The Server Password Exceeds 32 Characters" fullword ascii
		$s13 = "Service Name: %s" fullword ascii
		$s14 = "Server Password: %s" fullword ascii
		$s17 = "Inject Process Name: %s" fullword ascii

		$x1 = "WinEggDrop Shell Congirator" fullword ascii
	condition:
		5 of ($s*) or $x1
}