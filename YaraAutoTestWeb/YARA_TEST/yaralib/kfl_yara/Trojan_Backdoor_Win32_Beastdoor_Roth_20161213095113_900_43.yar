rule Trojan_Backdoor_Win32_Beastdoor_Roth_20161213095113_900_43 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Beastdoor.Roth"
		threattype = "BackDoor"
		family = "Beastdoor"
		hacker = "None"
		refer = "76b09b2ecf350a52944820b29718750e"
		description = "Detects the backdoor Beastdoor"
		comment = "None"
		author = "Djw,Florian Roth"
		date = "2016-06-23"
	strings:
		$s0 = "Redirect SPort RemoteHost RPort  -->Port Redirector" fullword
		$s1 = "POST /scripts/WWPMsg.dll HTTP/1.0" fullword
		$s2 = "http://IP/a.exe a.exe            -->Download A File" fullword
		$s7 = "Host: wwp.mirabilis.com:80" fullword
		$s8 = "%s -Set Port PortNumber              -->Set The Service Port" fullword
		$s11 = "Shell                            -->Get A Shell" fullword
		$s14 = "DeleteService ServiceName        -->Delete A Service" fullword
		$s15 = "Getting The UserName(%c%s%c)-->ID(0x%s) Successfully" fullword
		$s17 = "%s -Set ServiceName ServiceName      -->Set The Service Name" fullword

	condition:
		2 of them
}
