rule Trojan_Hacktool_Win32_Equation_3xRIDEA_631_414
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.3xRIDEA"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "7c2d0117fa3e714215120d3c14665c56"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-20"
        description = "Equation Group hack tool set xxxRIDEAREA "
	strings:
		$x1 = "USAGE: %s -i InputFile -o OutputFile [-f FunctionOrdinal] [-a FunctionArgument] [-t ThreadOption]" fullword ascii
		$x2 = "The output payload \"%s\" has a size of %d-bytes." fullword ascii
		$x3 = "ERROR: fwrite(%s) failed on ucPayload" fullword ascii
		$x4 = "Load and execute implant within the existing thread" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}