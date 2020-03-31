rule Trojan_HackTool_Win32_RunasEx_A_1017
{
	meta:
		judge = "black"
		threatname = "Trojan[HackTool]/Win32.RunasEx.A"
		threattype = "HackTool"
		family = "RunasEx"
		hacker = "None"
		refer = "45da17b2d257de8d5531e12b61955389"
		comment = "None"
		description = "Disclosed hacktool set (old stuff) - file RunAsEx.exe"
		author = "Florian Roth -lz"
		date = "23.11.14"
		
	strings:
		$s0 = "RunAsEx By Assassin 2000. All Rights Reserved. http://www.netXeyes.com" fullword ascii
		$s8 = "cmd.bat" fullword ascii
		$s9 = "Note: This Program Can'nt Run With Local Machine." fullword ascii
		$s11 = "%s Execute Succussifully." fullword ascii
		$s12 = "winsta0" fullword ascii
		$s15 = "Usage: RunAsEx <UserName> <Password> <Execute File> [\"Execute Option\"]" fullword ascii
	condition:
		4 of them
}