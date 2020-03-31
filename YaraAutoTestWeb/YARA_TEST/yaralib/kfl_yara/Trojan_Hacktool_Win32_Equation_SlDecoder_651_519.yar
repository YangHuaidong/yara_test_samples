rule Trojan_Hacktool_Win32_Equation_SlDecoder_651_519
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.SlDecoder"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "1f90b841aba14fb994853ff2085c3b0a"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-27"
        description = "Equation Group hack tool set SlDecoder "
	strings:
		$x1 = "Error in conversion. SlDecoder.exe <input filename> <output filename> at command line " fullword wide
		$x2 = "KeyLogger_Data" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}	