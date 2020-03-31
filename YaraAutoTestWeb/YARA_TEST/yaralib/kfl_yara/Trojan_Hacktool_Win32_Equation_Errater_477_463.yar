rule Trojan_Hacktool_Win32_Equation_Errater_477_463
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.Errater"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "b4cb23d33c82bb66a7edcfe85e9d5361"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-30"
        description = "Equation Group hack tool set EquationGroup_Toolset_Apr17_Erraticgopher_1_0_1 "
	strings:
		$x1 = "[-] Error appending shellcode buffer" fullword ascii
		$x2 = "[-] Shellcode is too big" fullword ascii
		$x3 = "[+] Exploit Payload Sent!" fullword ascii
		$x4 = "[+] Bound to Dimsvc, sending exploit request to opnum 29" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 150KB and 1 of them )
}