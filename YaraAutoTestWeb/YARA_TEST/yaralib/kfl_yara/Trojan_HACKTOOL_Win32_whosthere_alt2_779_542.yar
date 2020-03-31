rule Trojan_HACKTOOL_Win32_whosthere_alt2_779_542
{
	meta:

	    judge = "black"
	    threatname = "Trojan[HACKTOOL]/Win32.whosthere.alt2"
	    threattype = "HACKTOOL"
	    family = "whosthere"
	    hacker = "None"
	    refer = "15467a8e0d473a9e85c42035a0496e0e"
	    comment = "None"
		description = "Auto-generated rule - file pth.dll"
		author = "Florian Roth -lz"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		date = "2015-07-10"

	strings:
		$s0 = "c:\\debug.txt" fullword ascii /* PEStudio Blacklist: strings */ /* score: '23.00' */
		$s1 = "pth.dll" fullword ascii /* score: '20.00' */
		$s2 = "\"Primary\" string found at %.8Xh" fullword ascii /* score: '7.00' */
		$s3 = "\"Primary\" string not found!" fullword ascii /* score: '6.00' */
		$s4 = "segment 1 found at %.8Xh" fullword ascii /* score: '6.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 240KB and 4 of them
}