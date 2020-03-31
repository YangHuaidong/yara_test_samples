rule Trojan_HACKTOOL_Win32_whosthere_alt_778_543

{
	meta:
		judge = "black"
	    threatname = "Trojan[HACKTOOL]/Win32.whosthere.alt"
	    threattype = "HACKTOOL"
	    family = "whosthere"
	    hacker = "None" 
	    refer = "c89d4d40e4b68a9952121b62b0dda920"
	    comment = "None"
		description = "Auto-generated rule - file whosthere-alt.exe"
		author = "Florian Roth"
		date = "2015-07-10"

	strings:
		$s0 = "WHOSTHERE-ALT v1.1 - by Hernan Ochoa (hochoa@coresecurity.com, hernan@gmail.com) - (c) 2007-2008 Core Security Technologies" fullword ascii /* PEStudio Blacklist: strings */ /* score: '49.00' */
		$s1 = "whosthere enters an infinite loop and searches for new logon sessions every 2 seconds. Only new sessions are shown if found." fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.00' */
		$s2 = "dump output to a file, -o filename" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00' */
		$s3 = "This tool lists the active LSA logon sessions with NTLM credentials." fullword ascii /* PEStudio Blacklist: strings */ /* score: '29.00' */
		$s4 = "Error: pth.dll is not in the current directory!." fullword ascii /* score: '24.00' */
		$s5 = "the output format is: username:domain:lmhash:nthash" fullword ascii /* PEStudio Blacklist: strings */ /* score: '17.00' */
		$s6 = ".\\pth.dll" fullword ascii /* score: '16.00' */
		$s7 = "Cannot get LSASS.EXE PID!" fullword ascii /* score: '14.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 280KB and 2 of them
}