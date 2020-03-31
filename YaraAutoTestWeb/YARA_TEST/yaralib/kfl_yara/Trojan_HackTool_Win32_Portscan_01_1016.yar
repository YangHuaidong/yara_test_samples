rule Trojan_HackTool_Win32_Portscan_01_1016 
{
	meta:
		judge = "black"
	    threatname = "Trojan[HackTool]/Win32.Portscan.01"
	    threattype = "HackTool"
	    family = "Portscan"
	    hacker = "None"
	    refer = "4ac8b5bc5ab30f563e8d8b2980e2b249"
	    comment = "None"
		description = "Detects a Chinese hacktool from a disclosed toolset - file LScanPortss.exe"
		author = "Florian Roth"	
		date = "2015/03/30"
		
	strings:
		$s1 = "LScanPort.EXE" fullword wide
		$s3 = "www.honker8.com" fullword wide
		$s4 = "DefaultPort.lst" fullword ascii
		$s5 = "Scan over.Used %dms!" fullword ascii
		$s6 = "www.hf110.com" fullword wide
		$s15 = "LScanPort Microsoft " fullword wide
		$s18 = "L-ScanPort2.0 CooFly" fullword wide
	condition:
		4 of them
}
