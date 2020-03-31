rule Trojan_DDoS_Win32_Nitol_A_694
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Nitol.A"
		threattype = "DDoS"
		family = "Nitol"
		hacker = "None"
		refer = "70cec4325ac62131e7731a90d5d2e730"
		author = "LiuGuangZhu"
		comment = "None"
		date = "2018-08-16"
		description = "None"

	strings:		
		$s0 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"
		$s1 = "CopyFileA"
		$s2 = "OpenSCManagerA"
		$s3 = "CreateMutexA"
		$s4 = "SHELL32.dll"
		$s5 = "SHLWAPI.dll"
		$s6 = "iphlpapi.dll"
		$s7 = "MFC42.DLL"
		$s8 = "RegisterServiceCtrlHandlerA"
		$s9 = "UnlockServiceDatabase"
		$s10 = "GetSystemDirectoryA"
		$s11 = "%d*%u%s"
		$s12 = "%s %s%d"
		$s13 = "%u MB"
		$s14 = "%s %s%s"
		$s15 = "ChangeServiceConfig2A"
		//$s16 = "%c%c%c%c%ccn.exe"
	condition:
		all of them
}