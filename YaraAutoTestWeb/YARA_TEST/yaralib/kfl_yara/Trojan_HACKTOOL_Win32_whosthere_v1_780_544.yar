rule Trojan_HACKTOOL_Win32_whosthere_v1_780_544
{
	meta:

	    judge = "black"
	    threatname = "Trojan[HACKTOOL]/Win32.whosthere.v1"
	    threattype = "HACKTOOL"
	    family = "whosthere"
	    hacker = "None"
	    refer = "79d95610875d18dd908c9a36aee8612d"
	    comment = "None"
		description = "Auto-generated rule - file whosthere.exe"
		author = "Florian Roth -lz"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		date = "2015-07-10"
		
	strings:
		$s1 = "by Hernan Ochoa (hochoa@coresecurity.com, hernan@gmail.com) - (c) 2007-2008 Core Security Technologies" fullword ascii /* PEStudio Blacklist: strings */ /* score: '48.00' */
		$s2 = "whosthere enters an infinite loop and searches for new logon sessions every 2 seconds. Only new sessions are shown if found." fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.00' */
		$s3 = "specify addresses to use. Format: ADDCREDENTIAL_ADDR:ENCRYPTMEMORY_ADDR:FEEDBACK_ADDR:DESKEY_ADDR:LOGONSESSIONLIST_ADDR:LOGONSES" ascii /* PEStudio Blacklist: strings */ /* score: '28.00' */
		$s4 = "Could not enable debug privileges. You must run this tool with an account with administrator privileges." fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00' */
		$s5 = "-B is now used by default. Trying to find correct addresses.." fullword ascii /* PEStudio Blacklist: strings */ /* score: '15.00' */
		$s6 = "Cannot get LSASS.EXE PID!" fullword ascii /* score: '14.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 320KB and 2 of them
}
