rule Trojan_Hacktool_Win32_Equation_DUMPEL_602_449
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.DUMPEL"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "976db6bcba67597965df42d04cda8443"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-08-13"
        description = "Equation Group hack tool set DUMPEL "
	strings:
		$x1 = "dumpel -f file [-s \\\\server]" fullword ascii
		$x2 = "records will not appear in the dumped log." fullword ascii
		$x3 = "obj\\i386\\Dumpel.exe" fullword ascii
		$s13 = "DUMPEL Usage:    " fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}