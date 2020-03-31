rule Trojan_Hacktool_Win32_Equation_DiBa2K_635_439
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.DiBa2K"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "e2962b72552918888d6df9b254355880"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-27"
        description = "Equation Group hack tool set DiBa_Target_BH_2000 "
	strings:
		$s2 = "0M1U1Z1p1" fullword ascii /* base64 encoded string '3U5gZu' */
		$s14 = "SPRQWV" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}