rule Trojan_Hacktool_Win32_Equation_EXPA_584_475
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.EXPA"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "70aaa1428ad2eaf251073a4d887041f6"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-08-13"
        description = "Equation Group hack tool set EXPA "
	strings:
		$x1 = "* The target is IIS 6.0 but is not running content indexing servicess," fullword ascii
		$x2 = "--ver 6 --sp <service_pack> --lang <language> --attack shellcode_option[s]sL" fullword ascii
		$x3 = "By default, the shellcode will attempt to immediately connect s$" fullword ascii
		$x4 = "UNEXPECTED SHELLCODE CONFIGURATION ERRORs" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 12000KB and 1 of them )
}