rule Trojan_Hacktool_Win32_Equation_yakmin_653_528
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.yakmin"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "654bb3438b7f8c9e2fb9c5ca96140870"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-08-20"
        description = "Equation Group hack tool set yak_min_install "
	strings:
		$s1 = "driver start" fullword ascii
		$s2 = "DeviceIoControl Error: %d" fullword ascii
		$s3 = "Phlook" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}