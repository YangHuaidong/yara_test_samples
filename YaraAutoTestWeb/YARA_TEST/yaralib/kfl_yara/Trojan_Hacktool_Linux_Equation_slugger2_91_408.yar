rule Trojan_Hacktool_Linux_Equation_slugger2_91_408
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Linux.Equation.slugger2"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "16799b3e64c63a911200ab076318e41f"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-09"
        description = "Equation Group hack tool leaked by ShadowBrokers- file slugger2"
	strings:
		$x1 = "usage: %s hostip port cmd [printer_name]" fullword ascii
		$x2 = "command must be less than 61 chars" fullword ascii
		$s1 = "__rw_read_waiting" fullword ascii
		$s2 = "completed.1" fullword ascii
		$s3 = "__mutexkind" fullword ascii
		$s4 = "__rw_pshared" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 50KB and ( 4 of them and 1 of ($x*) ) ) or ( all of them )
}