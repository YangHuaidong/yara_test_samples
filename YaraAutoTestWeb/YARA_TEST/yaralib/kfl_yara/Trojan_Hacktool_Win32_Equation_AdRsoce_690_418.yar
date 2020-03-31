rule Trojan_Hacktool_Win32_Equation_AdRsoce_690_418
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.AdRsoce"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "ac95267fcfbbca0ccac0ad61307ed3c6,f94dba5426d11a6de13ee56c849d2703"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-09-03"
        description = "Equation Group hack tool set AddResource "
	strings:
		$s1 = "%s cm 10 2000 \"c:\\MY DIR\\myapp.exe\" c:\\MyResourceData.dat" fullword ascii
		$s2 = "<PE path> - the path to the PE binary to which to add the resource." fullword ascii
		$s3 = "Unable to get path for target binary." fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 300KB and 2 of them )
}