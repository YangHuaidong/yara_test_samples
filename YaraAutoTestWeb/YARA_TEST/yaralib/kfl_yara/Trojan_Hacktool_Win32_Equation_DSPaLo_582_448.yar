rule Trojan_Hacktool_Win32_Equation_DSPaLo_582_448
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.DSPaLo"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "0a6c1229f54f47bc9b6ffb964b42ed04"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-08-13"
        description = "Equation Group hack tool set DS_ParseLogs "
	strings:
		$x1 = "* Size (%d) of remaining capture file is too small to contain a valid header" fullword wide
		$x2 = "* Capture header not found at start of buffer" fullword wide
		$x3 = "Usage: %ws <capture_file> <results_prefix>" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}