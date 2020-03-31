rule Trojan_HackTool_Win32_IIsclean_A_1014 
{
	meta:
		judge = "black"
		threatname = "Trojan[HackTool]/Win32.IIsclean.A"
		threattype = "HackTool"
		family = "IIsclean"
		hacker = "None"
		refer = "6887668c0f6d442e80e66e4faccabfdf"
		comment = "None"
		description = "Disclosed hacktool set (old stuff) - file CleanIISLog.exe"
		author = "Florian Roth -lz"
		date = "23.11.14"
	
	strings:
		$s1 = "CleanIP - Specify IP Address Which You Want Clear." fullword ascii
		$s2 = "LogFile - Specify Log File Which You Want Process." fullword ascii
		$s8 = "CleanIISLog Ver" fullword ascii
		$s9 = "msftpsvc" fullword ascii
		$s10 = "Fatal Error: MFC initialization failed" fullword ascii
		$s11 = "Specified \"ALL\" Will Process All Log Files." fullword ascii
		$s12 = "Specified \".\" Will Clean All IP Record." fullword ascii
		$s16 = "Service %s Stopped." fullword ascii
		$s20 = "Process Log File %s..." fullword ascii
	condition:
		5 of them
}