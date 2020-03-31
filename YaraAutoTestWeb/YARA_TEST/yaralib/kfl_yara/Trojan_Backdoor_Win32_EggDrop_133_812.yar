rule Trojan_Backdoor_Win32_EggDrop_133_812
{
	meta:
	    judge = "black"
	    threatname = "Trojan[Backdoor]/Win32.EggDrop.133"
	    threattype = "Backdoor"
	    family = "EggDrop"
	    hacker = "None"
	    refer = "b5d26cec5ee6ff68777833be4532cc23"
	    comment = "None"
	    date = "2018-07-30"
		description = "Detects the backdoor Beastdoor"
		author = "Florian Roth -lz "
		
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