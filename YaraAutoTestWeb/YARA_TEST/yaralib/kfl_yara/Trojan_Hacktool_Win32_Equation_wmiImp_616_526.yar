rule Trojan_Hacktool_Win32_Equation_wmiImp_616_526
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.wmiImp"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "998087c45563ab2d597bf0590b5d6cb4"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-20"
        description = "Equation Group hack tool set wmi_Implant "
	strings:
		$x1 = "SELECT ProcessId,Description,ExecutablePath FROM Win32_Process" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 50KB and all of them )
}