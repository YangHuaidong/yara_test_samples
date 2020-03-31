rule Trojan_Hacktool_Win32_Equation_Excaouch_480_474
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.Excaouch"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "96affb296584515614dd1e6675dce57c"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-24"
        description = "Equation Group hack tool set EquationGroup_Toolset_Apr17_Explodingcantouch_1_2_1 "
	strings:
		$x1 = "[-] Connection closed by remote host (TCP Ack/Fin)" fullword ascii
		$s2 = "[!]Warning: Error on first request - path size may actually be larger than indicated." fullword ascii
		$s4 = "<http://%s/%s> (Not <locktoken:write1>) <http://%s/>" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 150KB and 1 of them )
}