rule Trojan_Backdoor_Win32_IronGate_Step7ProSim_1090
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.IronGate.Step7ProSim"
		threattype = "ICS,Backdoor"
		family = "IronGate"
		hacker = "None"
		refer = "874f7bcab71f4745ea6cda2e2fb5a78c"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-03-21"
		description = "https://github.com/Neo23x0/signature-base/blob/master/yara/apt_irongate.yar"
	strings:
		$x1 = "\\obj\\Release\\Step7ProSim.pdb" ascii
		$s1 = "Step7ProSim.Interfaces" fullword ascii
		$s2 = "payloadExecutionTimeInMilliSeconds" fullword ascii
		$s3 = "PackagingModule.Step7ProSim.dll" fullword wide
		$s4 = "<KillProcess>b__0" fullword ascii
		$s5 = "newDllFilename" fullword ascii
		$s6 = "PackagingModule.exe" fullword wide
		$s7 = "$863d8af0-cee6-4676-96ad-13e8540f4d47" fullword ascii
		$s8 = "RunPlcSim" fullword ascii
		$s9 = "$ccc64bc5-ef95-4217-adc4-5bf0d448c272" fullword ascii
		$s10 = "InstallProxy" fullword ascii
		$s11 = "DllProxyInstaller" fullword ascii
		$s12 = "FindFileInDrive" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 50KB and ( $x1 or 3 of ($s*) ) )
		or ( 6 of them )
}