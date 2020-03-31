rule Trojan_Backdoor_Win32_Industroyer_Portscan_Output_1081
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Industroyer.Portscan.Output"
		threattype = "ICS,Backdoor"
		family = "Industroyer"
		hacker = "None"
		refer = "497de9d388d23bf8ae7230d80652af69"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-03-21"
		description = "https://github.com/Yara-Rules/rules/blob/master/malware/APT_Industroyer.yar"
	strings:
		$s1 = "WSA library load complite." fullword ascii
		$s2 = "Connection refused" fullword ascii
	condition:
		all of them
}