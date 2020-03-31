rule Trojan_Hacktool_Win32_Equation_SetPorts_615_518
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.SetPorts"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "874e882e93f2950c123cec411dcd2d9d"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-20"
        description = "Equation Group hack tool set SetPorts "
	strings:
		$s1 = "USAGE: SetPorts <input file> <output file> <version> <port1> [port2] [port3] [port4] [port5]" fullword ascii
		$s2 = "Valid versions are:  1 = PC 1.2   2 = PC 1.2 (24 hour)" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}