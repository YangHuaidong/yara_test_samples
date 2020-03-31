rule Trojan_Backdoor_Win32_Pipecmd_A_1009
{
	meta:
	    judge = "black"
	    threatname = "Trojan[Backdoor]/Win32.Pipecmd.A"
	    threattype = "Backdoor"
	    family = "Pipecmd"
	    hacker = "None"
	    refer = "7933a0f995aca800a38ea7e37d6c62ca"
	    comment = "None"
		description = "Detects a Chinese hacktool from a disclosed toolset - file PipeCmd.exe"
		author = "Florian Roth -lz"
		date = "2015/03/30"	

	strings:
		$s2 = "Please Use NTCmd.exe Run This Program." fullword ascii
		$s3 = "PipeCmd.exe" fullword wide
		$s4 = "\\\\.\\pipe\\%s%s%d" fullword ascii
		$s5 = "%s\\pipe\\%s%s%d" fullword ascii
		$s6 = "%s\\ADMIN$\\System32\\%s%s" fullword ascii
		$s7 = "%s\\ADMIN$\\System32\\%s" fullword ascii
		$s9 = "PipeCmdSrv.exe" fullword ascii
		$s10 = "This is a service executable! Couldn't start directly." fullword ascii
		$s13 = "\\\\.\\pipe\\PipeCmd_communicaton" fullword ascii
		$s14 = "PIPECMDSRV" fullword wide
		$s15 = "PipeCmd Service" fullword ascii
	condition:
		4 of them
}