rule Trojan_Hacktool_Linux_Equation_DUL_79_384
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Linux.Equation.DUL"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "f58db476486145aaf4958194e14c2404"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-09"
        description = "Equation Group hack tool leaked by ShadowBrokers- file DUL"
	strings:
		$x1 = "?Usage: %s <shellcode> <output_file>" fullword ascii
		$x2 = "Here is the decoder+(encoded-decoder)+payload" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 80KB and 1 of them ) or ( all of them )
}