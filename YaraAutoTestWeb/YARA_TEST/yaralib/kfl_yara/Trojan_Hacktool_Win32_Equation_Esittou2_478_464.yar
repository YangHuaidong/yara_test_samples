rule Trojan_Hacktool_Win32_Equation_Esittou2_478_464
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.Esittou2"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "e30d66be8ddf31f44bb66b8c3ea799ae"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-30"
        description = "Equation Group hack tool set Esittou2"
	strings:
		$x1 = "[-] Touching the target failed!" fullword ascii
		$x2 = "[-] OS fingerprint not complete - 0x%08x!" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}