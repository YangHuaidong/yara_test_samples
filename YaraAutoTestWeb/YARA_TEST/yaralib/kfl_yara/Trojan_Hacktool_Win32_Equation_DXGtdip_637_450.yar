rule Trojan_Hacktool_Win32_Equation_DXGtdip_637_450
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.DXGtdip"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "74de13b5ea68b3da24addc009f84baee,4a184a987d297e6b1d578d5c25a4980c,20506375665a6a62f7d9dd22d1cc9870"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-20"
        description = "Equation Group hack tool set mstcp32_DXGHLP16_tdip "
	strings:
		$s1 = "\\Registry\\User\\CurrentUser\\" fullword wide
		$s2 = "\\DosDevices\\%ws" fullword wide
		$s3 = "\\Device\\%ws_%ws" fullword wide
		$s4 = "sys\\mstcp32.dbg" fullword ascii
		$s5 = "%ws%03d%ws%wZ" fullword wide
		$s6 = "TCP/IP driver" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and 4 of them )
}