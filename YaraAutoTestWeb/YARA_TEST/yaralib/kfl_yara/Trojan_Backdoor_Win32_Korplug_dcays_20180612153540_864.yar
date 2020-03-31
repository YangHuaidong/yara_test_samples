rule Trojan_Backdoor_Win32_Korplug_dcays_20180612153540_864 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Korplug.dcays"
		threattype = "BackDoor"
		family = "Korplug"
		hacker = "None"
		refer = "81df89d6fa0b26cadd4e50ef5350f341"
		description = "None"
		comment = "None"
		author = "David Cannings-copy"
		date = "2018-05-30"
	strings:
		$s0 = "Feb 04 2015"
		$s1 = "I can not start %s"
		$s2 = "dwConnectPort" fullword ascii
		$s3 = "dwRemoteLanPort" fullword ascii
		$s4 = "strRemoteLanAddress" fullword ascii
		$s5 = "strLocalConnectIp" fullword ascii
		$s6 = "\\\\.\\pipe\\NamePipe_MoreWindows" wide ascii
		$s7 = "RedLeavesCMDSimulatorMutex" wide ascii
		$s8 = "(NT %d.%d Build %d)" wide ascii
		$s9 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET4.0C; .NET4.0E)" wide ascii
		$s10 = "red_autumnal_leaves_dllmain.dll" wide ascii
		$11 = "__data" wide ascii
		$s12 = "__serial" wide ascii
		$s13 = "__upt" wide ascii
		$s14 = "__msgid" wide ascii

	condition:
		7 of them
}
