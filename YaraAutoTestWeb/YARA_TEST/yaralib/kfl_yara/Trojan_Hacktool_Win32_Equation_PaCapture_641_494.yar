rule Trojan_Hacktool_Win32_Equation_PaCapture_641_494
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.PaCapture"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "572f3772c6e03b0bd020291fe99739f3"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-27"
        description = "Equation Group hack tool set ParseCapture "
	strings:
		$x1 = "* Encrypted log found.  An encryption key must be provided" fullword ascii
		$x2 = "encryptionkey = e.g., \"00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff\"" fullword ascii
		$x3 = "Decrypting with key '%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x'" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 50KB and 1 of them )
}	