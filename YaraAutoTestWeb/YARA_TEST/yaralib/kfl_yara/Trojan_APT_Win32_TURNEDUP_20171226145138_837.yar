rule Trojan_APT_Win32_TURNEDUP_20171226145138_837 
{
	meta:
		judge = "black"
		threatname = "Trojan[APT]/Win32.TURNEDUP"
		threattype = "APT"
		family = "TURNEDUP"
		hacker = "None"
		refer = "c57c5529d91cffef3ec8dadf61c5ffb2"
		description = "None"
		comment = "None"
		author = "xc"
		date = "2017-12-13"
	strings:
		$s0 = "StikyNote.exe" nocase wide ascii
		$s1 = "aaaccccccccccbbbbbbnnnnnnnnnnnbbbbvvv" nocase wide ascii
		$s2 = ":\\Windows\\system32\\cmd.exe" nocase wide ascii
		$s3 = "iexplore.exe" nocase wide ascii
		$s4 = "/file/download/key/" nocase wide ascii
		$s5 = "gdiplus.dll" nocase wide ascii
		$s6 = "StikyNote2.exe" nocase wide ascii
		$s7 = "tskill %d\n" nocase wide ascii
		$s8 = "ping 1.0.0.0 -n 1 -w 20000 > nul\n" nocase wide ascii
		$s9 = "start /d \"%s\" %s\n" nocase wide ascii
		$s10 = "move \"%s\" \"%s\"\n" nocase wide ascii
		$s11 = "xman_1365_x\\" nocase wide ascii

	condition:
		8 of them
}
