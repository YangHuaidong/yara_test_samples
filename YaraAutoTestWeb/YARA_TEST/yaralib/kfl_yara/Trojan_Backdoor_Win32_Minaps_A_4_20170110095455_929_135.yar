rule Trojan_Backdoor_Win32_Minaps_A_4_20170110095455_929_135 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Minaps.A"
		threattype = "rat"
		family = "Minaps"
		hacker = "None"
		refer = "fe406edae9e73293e61f770630f29b4b,6e67fc27a49769f5218824d405d8fce5,6e38dc5689c28b66e4cc72ba22ab3493,6b14351ba454bcbfccbaf213f83a1282"
		description = "CommentCrew Malware MiniASP APT"
		comment = "None"
		author = "Florian Roth"
		date = "2015-06-03"
	strings:
		$x1 = "\\MiniAsp4\\Release\\MiniAsp.pdb" ascii
		$x2 = "run http://%s/logo.png setup.exe" fullword ascii
		$x3 = "d:\\command.txt" fullword ascii
		$z1 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR " ascii
		$z2 = "Mozilla/4.0 (compatible; MSIE 7.4; Win32;32-bit)" fullword ascii
		$z3 = "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC" ascii
		$s1 = "http://%s/device_command.asp?device_id=%s&cv=%s&command=%s" fullword ascii
		$s2 = "kill process error!" fullword ascii
		$s3 = "kill process success!" fullword ascii
		$s4 = "pickup command error!" fullword ascii
		$s5 = "http://%s/record.asp?device_t=%s&key=%s&device_id=%s&cv=%s&result=%s" fullword ascii
		$s6 = "no command" fullword ascii
		$s7 = "software\\microsoft\\windows\\currentversion\\run" fullword ascii
		$s8 = "command is null!" fullword ascii
		$s9 = "pickup command Ok!" fullword ascii

	condition:
		uint16(0) == 0x5a4d and 
( 1 of ($x*) ) or 
( all of ($z*) ) or 
( 8 of ($s*) )
}
