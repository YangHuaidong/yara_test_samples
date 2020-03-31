rule Trojan_Backdoor_Win32_Duqu2_Drivers_1082
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Duqu2.Drivers"
		threattype = "ICS,Backdoor"
		family = "Duqu2"
		hacker = "None"
		refer = "7699d7e0c7d6b2822992ad485caacb3e"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-03-21"
		description = "https://github.com/Yara-Rules/rules/blob/master/malware/APT_Duqu2.yar"
    strings:
		$a1 = "\\DosDevices\\port_optimizer" wide nocase 
		$a2 = "romanian.antihacker" 
		$a3 = "PortOptimizerTermSrv" wide 
		$a4 = "ugly.gorilla1"
		$b1 = "NdisIMCopySendCompletePerPacketInfo" 
		$b2 = "NdisReEnumerateProtocolBindings"
		$b3 = "NdisOpenProtocolConfiguration"
	condition:
		uint16(0) == 0x5A4D and (any of ($a*) ) and (2 of ($b*)) and filesize < 100000
}