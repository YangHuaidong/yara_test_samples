rule Trojan_Hacktool_Win32_Equation_SCabaPo_648_513
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.SCabaPo"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "d370d8114860747b40747ffa83d38db2"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-27"
        description = "Equation Group hack tool set SetCallbackPorts "
	strings:
		$s1 = "USAGE: %s <input file> <output file> <port1> [port2] [port3] [port4] [port5] [port6]" fullword ascii
		$s2 = "You may enter between 1 and 6 ports to change the defaults." fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}