rule Trojan_Hacktool_Win32_Equation_WdIplt_707_525
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.WdIplt"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "68a7f69f866881dfbd781169a35bb7b9"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-09-03"
        description = "Equation Group hack tool set Windows_Implant "
	strings:
		$s2 = "0#0)0/050;0M0Y0h0|0" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 50KB and all of them )
}