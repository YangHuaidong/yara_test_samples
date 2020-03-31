rule Trojan_Hacktool_Win32_Equation_stlp_593_522
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.stlp"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "48475af653e2876d3d36ac49d9439a5b"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-08-13"
        description = "Equation Group hack tool set st_lp "
	strings:
		$x1 = "Previous command: set injection processes (status=0x%x)" fullword ascii
		$x2 = "Secondary injection process is <null> [no secondary process will be used]" fullword ascii
		$x3 = "Enter the address to be used as the spoofed IP source address (xxx.xxx.xxx.xxx) -> " fullword ascii
		$x4 = "E: Execute a Command on the Implant" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 300KB and 1 of them )
}