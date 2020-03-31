rule Trojan_Hacktool_Win32_Equation_RExTa_590_512
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.RExTa"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "4567dd29ee4b60270c877b4d2364622c"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-08-13"
        description = "Equation Group hack tool set RemoteExecute_Target "
	strings:
		$s1 = "Win32_Process" fullword ascii
		$s2 = "\\\\%ls\\root\\cimv2" fullword wide
		$op1 = { 83 7b 18 01 75 12 83 63 }
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}