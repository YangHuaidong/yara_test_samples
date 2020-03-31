rule Trojan_Hacktool_Win32_Equation_SReNa_592_521
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.SReNa"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "4a6ff8ff5bab5d2c45107c8169a23078"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-08-13"
        description = "Equation Group hack tool set SetResourceName "
	strings:
		$x1 = "Updates the name of the dll or executable in the resource file" fullword ascii
		$x2 = "*NOTE: SetResourceName does not work with PeddleCheap versions" fullword ascii
		$x3 = "2 = [appinit.dll] level4 dll" fullword ascii
		$x4 = "1 = [spcss32.exe] level3 exe" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}