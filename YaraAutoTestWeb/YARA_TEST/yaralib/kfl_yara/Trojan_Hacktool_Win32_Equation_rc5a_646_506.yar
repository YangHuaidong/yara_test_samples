rule Trojan_Hacktool_Win32_Equation_rc5a_646_506
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.rc5a"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "6cc538d734ce8806a82ef771eed190ef"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-27"
        description = "Equation Group hack tool set rc5 "
	strings:
		$s1 = "Usage: %s [d|e] session_key ciphertext" fullword ascii
		$s2 = "where session_key and ciphertext are strings of hex" fullword ascii
		$s3 = "d = decrypt mode, e = encrypt mode" fullword ascii
		$s4 = "Bad mode, should be 'd' or 'e'" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and 2 of them )
}	