rule Trojan_Hacktool_Win32_Equation_EcprPc_473_452
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.EcprPc"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "195efb4a896e41fe49395c3c165a5d2e,460bc972466813b80c9be900e56302b6,4c266bf82c5e28e20edb52d557a40e1d"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-24"
        description = "Equation Group hack tool set EquationGroup_Toolset_Apr17_Eclipsedwing_Rpcproxy_Pcdlllauncher "
	strings:
		$x1 = "[-] Failed to Prepare Payload!" fullword ascii
		$x2 = "ShellcodeStartOffset" fullword ascii
		$x3 = "[*] Waiting for AuthCode from exploit" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}