rule Trojan_Hacktool_Win32_Equation_Doupu_472_445
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.Doupu"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "c24315b0585b852110977dacafe6c8c1"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-30"
        description = "Equation Group hack tool set EquationGroup_Toolset_Apr17_Doublepulsar_1_3_1 "
	strings:
		$x1 = "[+] Ping returned Target architecture: %s - XOR Key: 0x%08X" fullword ascii
		$x2 = "[.] Sending shellcode to inject DLL" fullword ascii
		$x3 = "[-] Error setting ShellcodeFile name" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}