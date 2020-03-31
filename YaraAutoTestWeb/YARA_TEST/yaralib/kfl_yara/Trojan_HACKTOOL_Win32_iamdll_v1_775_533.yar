rule Trojan_HACKTOOL_Win32_iamdll_v1_775_533
{
	meta:

	    judge = "black"
	    threatname = "Trojan[HACKTOOL]/Win32.iamdll.v1"
	    threattype = "HACKTOOL"
	    family = "iamdll"
	    hacker = "None"
	    refer = "1ad055c5d36f62cc6f936fe7786cf8a0"
	    comment = "None"
		description = "Auto-generated rule - file iamdll.dll"
		author = "Florian Roth -lz"
		date = "2015-07-10"
		
	strings:
		$s0 = "LSASRV.DLL" fullword ascii /* score: '21.00' */
		$s1 = "iamdll.dll" fullword ascii /* score: '21.00' */
		$s2 = "ChangeCreds" fullword ascii /* score: '12.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 115KB and all of them
}