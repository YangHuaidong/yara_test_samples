rule Trojan_Hacktool_Win32_Equation_creigrot_469_430
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.creigrot"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "8841538c0509d7f933a4f9f3f285d3a1,b9e13a778e0d37d0a2611d864403fe9e"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-24"
        description = "Equation Group hack tool set cursewham_curserazor_cursezinger_curseroot_win2k "
	strings:
		$s1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/%s,%s" fullword ascii
		$s3 = ",%02d%03d" fullword ascii
		$s4 = "[%.2u%.2u%.2u%.2u%.2u%.2u]" fullword ascii
		$op1 = { 7d ec 8d 74 3f 01 0f af f7 c1 c6 05 } /* Opcode */
		$op2 = { 29 f1 89 fb d3 eb 89 f1 d3 e7 } /* Opcode */
		$op3 = { 7d e4 8d 5c 3f 01 0f af df c1 c3 05 } /* Opcode */
	condition:
		( uint16(0) == 0x5a4d and filesize < 400KB and 3 of them )
}