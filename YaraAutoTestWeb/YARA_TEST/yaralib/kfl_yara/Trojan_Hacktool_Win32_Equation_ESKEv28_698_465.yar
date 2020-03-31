rule Trojan_Hacktool_Win32_Equation_ESKEv28_698_465
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.ESKEv28"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "22b6f3ae1a645e7bdf2b20682a1cb55e,a2ee4d67361d146f5c4aaa03e93b85e3"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-09-03"
        description = "Equation Group hack tool set ESKE_RPC2_8 "
	strings:
		$s4 = "Fragment: Packet too small to contain RPC header" fullword ascii
		$s5 = "Fragment pickup: SmbNtReadX failed" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 700KB and 1 of them )
}