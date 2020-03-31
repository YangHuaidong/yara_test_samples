rule Trojan_HackTool_Win32_TcpPipe_a_1018
{
	meta:

		judge = "black"
		threatname = "Trojan[HackTool]/Win32.TcpPipe.a"
		threattype = "HackTool"
		family = "TcpPipe"
		hacker = "None"
		refer = "4ee3412799bd2bf8580eae06c3c96b97"
		comment = "None"
		description = "Disclosed hacktool set (old stuff) - file FPipe2.0.exe"
		author = "Florian Roth -lz"
		date = "23.11.14"
	
	strings:
		$s0 = "made to port 80 of the remote machine at 192.168.1.101 with the" fullword ascii
		$s1 = "Unable to resolve hostname \"%s\"" fullword ascii
		$s2 = " -s    - outbound connection source port number" fullword ascii
		$s3 = "source port for that outbound connection being set to 53 also." fullword ascii
		$s4 = "http://www.foundstone.com" fullword ascii
		$s19 = "FPipe" fullword ascii
	condition:
		all of them
}