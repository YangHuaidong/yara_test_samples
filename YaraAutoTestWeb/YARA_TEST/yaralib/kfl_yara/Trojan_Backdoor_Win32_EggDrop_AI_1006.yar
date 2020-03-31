rule Trojan_Backdoor_Win32_EggDrop_AI_1006 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.EggDrop.AI"
		threattype = "Backdoor"
		family = "EggDrop"
		hacker = "None"
		refer = "57253df762908015f151d67de4ad50e1"
		comment = "None"
		description = "Disclosed hacktool set (old stuff) - file InjectT.exe"
		author = "Florian Roth -lz"
		date = "23.11.14"

	strings:
		$s0 = "Packed by exe32pack" ascii
		$s1 = "2TInject.Dll" fullword ascii
		$s2 = "Windows Services" fullword ascii
		$s3 = "Findrst6" fullword ascii
		$s4 = "Press Any Key To Continue......" fullword ascii
	condition:
		all of them
}