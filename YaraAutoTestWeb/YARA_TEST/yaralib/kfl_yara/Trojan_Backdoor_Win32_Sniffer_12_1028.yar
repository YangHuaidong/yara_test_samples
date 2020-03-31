rule Trojan_Backdoor_Win32_Sniffer_12_1028
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Sniffer.12"
		threattype = "Backdoor"
		family = "Sniffer"
		hacker = "None"
		refer = "91ce3ebc31edb0e8340fdebf325a1b51"
		comment = "None"
		description = "Disclosed hacktool set (old stuff) - file snifferport.exe"
		author = "Florian Roth"
		date = "23.11.14"
		
	strings:
		$s0 = "iphlpapi.DLL" fullword ascii
		$s5 = "ystem\\CurrentCorolSet\\" fullword ascii
		$s11 = "Port.TX" fullword ascii
		$s12 = "32Next" fullword ascii
		$s13 = "V1.2 B" fullword ascii
	condition:
		all of them
}