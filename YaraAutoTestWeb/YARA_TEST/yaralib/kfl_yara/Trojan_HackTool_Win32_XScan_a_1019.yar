rule Trojan_HackTool_Win32_XScan_a_1019
{
	meta:
	    judge = "black"
	    threatname = "Trojan[HackTool]/Win32.XScan.a"
	    threattype = "HackTool"
	    family = "XScan"
	    hacker = "None"
	    refer = "63ea81c804a7a3209df31f2e3798335c"
	    comment = "None"
		description = "Detects a Chinese hacktool from a disclosed toolset - from files XScanLib.dll, XScanLib.dll, XScanLib.dll"
		author = "Florian Roth -lz"	
		date = "2015/03/30"
		
	strings:
		$s1 = "Plug-in thread causes an exception, failed to alert user." fullword
		$s2 = "PlugGetUdpPort" fullword
		$s3 = "XScanLib.dll" fullword
		$s4 = "PlugGetTcpPort" fullword
		$s11 = "PlugGetVulnNum" fullword
	condition:
		all of them
}