rule Trojan_HACKTOOL_Win32_genhash_v1_772_530
{
	meta:
	    judge = "black"
	    threatname = "Trojan[HACKTOOL]/Win32.genhash.v1"
	    threattype = "HACKTOOL"
	    family = "genhash"
	    hacker = "None"	    
	    refer = "a80320e98f32484a7b5bf55e6f3e5d22"
	    comment = "None"
		description = "Auto-generated rule - file genhash.exe"
		author = "Florian Roth -lz"
		date = "2015-07-10"
		
	strings:
		$s1 = "genhash.exe <password>" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00' */
		$s3 = "Password: %s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '17.00' */
		$s4 = "%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X" fullword ascii /* score: '11.00' */
		$s5 = "This tool generates LM and NT hashes." fullword ascii /* score: '10.00' */
		$s6 = "(hashes format: LM Hash:NT hash)" fullword ascii /* score: '10.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and 2 of them
}