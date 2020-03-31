rule Trojan_Backdoor_Win32_GenericKD_aaaaaa_500_91
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.GenericKD.aaaaaa"
        threattype = "Backdoor"
        family = "GenericKD"
        hacker = "None"
        author = "balala"
        refer = "81df89d6fa0b26cadd4e50ef5350f341"
		comment = "None"
        date = "2018-07-30"
        description = "Red Leaves malware, related to APT10"
    strings:
    // MiniLZO release date
		$ = "Feb 04 2015"
		$ = "I can not start %s"
		$ = "dwConnectPort" fullword
		$ = "dwRemoteLanPort" fullword
		$ = "strRemoteLanAddress" fullword
		$ = "strLocalConnectIp" fullword
		$ = "\\\\.\\pipe\\NamePipe_MoreWindows" wide
		$ = "RedLeavesCMDSimulatorMutex" wide
		$ = "(NT %d.%d Build %d)" wide
		$ = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET4.0C; .NET4.0E)" wide
		$ = "red_autumnal_leaves_dllmain.dll" wide ascii
		$ = "__data" wide
		$ = "__serial" wide
		$ = "__upt" wide
		$ = "__msgid" wide
    
	condition:
		7 of them
}