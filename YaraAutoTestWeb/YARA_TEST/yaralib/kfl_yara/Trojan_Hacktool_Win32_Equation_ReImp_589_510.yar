rule Trojan_Hacktool_Win32_Equation_ReImp_589_510
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.ReImp"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "a9f90a3c00de155f811784d89aecc556"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-08-13"
        description = "Equation Group hack tool set RemoteExecute_Implant "
	strings:
		$op1 = { 53 00 63 00 68 00 65 00 64 00 75 00 6C 00 65 00 00 00 00 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 41 00 63 00 74 00 69 00 76 00 65 00 00 00 00 00 FF FF FF FF 00 00 00 00 B0 17 00 68 5C 00 70 00 69 00 70 00 65 00 5C 00 53 00 65 00 63 00 6F 00 6E 00 64 00 61 00 72 00 79 00 4C 00 6F 00 67 00 6F 00 6E 00 00 00 00 00 5C 00 00 00 57 00 69 00 6E 00 53 00 74 00 61 00 30 00 5C 00 44 00 65 00 66 00 61 00 75 00 6C 00 74 00 00 00 6E 00 63 00 61 00 63 00 6E 00 5F 00 6E 00 70 00 00 00 00 00 5C 00 70 00 69 00 70 00 65 00 5C 00 53 00 45 00 43 00 4C 00 4F 00 47 00 4F 00 4E }
	condition:
		( uint16(0) == 0x5a4d and filesize < 40KB and all of them )
}