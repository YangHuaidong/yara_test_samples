rule Trojan_Hacktool_Linux_Equation_wacherv3_465_410
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Linux.Equation.wacherv3"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "0278e9a2d718d8ef7b156c7131023911"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-30"
        description = "Equation Group hack tool set EquationGroup_watcher_linux_x86_64_v_3_3_0"
	strings:
		$s1 = "forceprismheader" fullword ascii
		$s2 = "invalid option `" fullword ascii
		$s3 = "forceprism" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 900KB and all of them )
}