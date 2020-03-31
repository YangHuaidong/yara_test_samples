rule Trojan_HackTool_Win32_gina_FakeGina_1013
{
	meta:

		judge = "black"
		threatname = "Trojan[HackTool]/Win32.gina.FakeGina"
		threattype = "HackTool"
		family = "gina"
		hacker = "None"
		refer = "b1fb9ac7063db57192db9bee04c50363"
		comment = "None"
		description = "Disclosed hacktool set (old stuff) - file gina.dll"
		author = "Florian Roth -lz"
		date = "23.11.14"

	strings:
		$s0 = "NEWGINA.dll" fullword ascii
		$s1 = "LOADER ERROR" fullword ascii
		$s3 = "WlxActivateUserShell" fullword ascii
		$s6 = "WlxWkstaLockedSAS" fullword ascii
		$s13 = "WlxIsLockOk" fullword ascii
		$s14 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii
		$s16 = "WlxShutdown" fullword ascii
		$s17 = "The ordinal %u could not be located in the dynamic link library %s" fullword ascii
	condition:
		all of them
}