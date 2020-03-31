rule Trojan_DDoS_Win32_Nitol_Aa_795
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Nitol.Aa"
		threattype = "DDoS"
		family = "Nitol"
		hacker = "None"
		refer = "7b486231a04b1a7006df896309d3ecd0"
		author = "LiuGuangZhu"
		comment = "None"
		date = "2018-08-17"
		description = "None"

	strings:		
		$s0 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"
		$s1 = "CopyFileA"
		$s2 = "OpenSCManagerA"
		$s3 = "CreateMutexA"
		$s4 = "SHELL32.dll"
		$s5 = "SHLWAPI.dll"
		$s6 = "iphlpapi.dll"
		$s7 = "RegisterServiceCtrlHandlerA"
		$s8 = "pdh.dll"
		$s9 = "SeDebugPrivilege"
		$s10 = {2F 63 20 64 65 6C}
		$s11 = {63 6D 64 20 2F 63 20 25 73}
		$s12 = "ShellExecuteExA"
		//$s13 = "gy.dat"
	condition:
		all of them
}