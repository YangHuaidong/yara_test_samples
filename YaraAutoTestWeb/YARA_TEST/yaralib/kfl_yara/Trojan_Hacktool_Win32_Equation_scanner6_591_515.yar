rule Trojan_Hacktool_Win32_Equation_scanner6_591_515
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.scanner6"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "98fd2854486c4232d52e3720e2971709"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-08-13"
        description = "Equation Group hack tool set scanner "
	strings:
		$x1 = "+daemon_version,system,processor,refid,clock" fullword ascii
		$x2 = "Usage: %s typeofscan IP_address" fullword ascii
		$x3 = "# scanning ip  %d.%d.%d.%d" fullword ascii
		$x4 = "Welcome to the network scanning tool" fullword ascii
		$x5 = "***** %s ***** (length %d)" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 90KB and 1 of them )
}