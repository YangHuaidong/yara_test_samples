rule Trojan_DDoS_Win32_Nitol_Ab_796
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Nitol.Ab"
		threattype = "DDoS"
		family = "Nitol"
		hacker = "None"
		refer = "223f1fc0df38ef8d3a971dd888503710"
		author = "LiuGuangZhu"
		comment = "None"
		date = "2018-08-17"
		description = "None"

	strings:		
		$s0 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"
		$s1 = "OpenMutexA"
		$s2 = "ShellExecuteA"
		$s3 = "SHELL32.dll"
		$s4 = "UnhandledExceptionFilter"
		$s5 = "%c%c%c%c%c.exe"
		$s6 = "URLDownloadToFileA"
		$s7 = "urlmon.dll"
		$s8 = "passthru.sys"
		$s9 = "snetcfg.exe"
		$s10 = "install.bat"
		$s11 = "netsf_m.inf"
		$s12 = "netsf.inf"
		$s13 = "%u MHz"
		$s14 = "snetcfg -v -l C:\\netsf.inf -c s -i  ms_passthru"
	condition:
		all of them
}