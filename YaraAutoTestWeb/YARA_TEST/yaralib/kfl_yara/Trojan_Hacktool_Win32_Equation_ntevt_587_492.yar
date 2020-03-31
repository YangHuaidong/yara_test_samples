rule Trojan_Hacktool_Win32_Equation_ntevt_587_492
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.ntevt"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "f9fdc58c2a3ea2c00d0caa3c33d6a575"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-08-13"
        description = "Equation Group hack tool set ntevt "
	strings:
		$x1 = "c:\\ntevt.pdb" fullword ascii
		$s1 = "ARASPVU" fullword ascii
		$op1 = { 41 5a 41 59 41 58 5f 5e 5d 5a 59 5b 58 48 83 c4 }
		$op2 = { f9 48 03 fa 48 33 c0 8a 01 49 03 c1 49 f7 e0 88 }
		$op3 = { 01 41 f6 e0 49 03 c1 88 01 48 33 }
	condition:
		( uint16(0) == 0x5a4d and filesize < 700KB and $x1 or 3 of them )
}