rule Trojan_Hacktool_Win32_Equation_PriScRev9_705_503
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.PriScRev9"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "530edfca04227e4a0abe2ea6aa0d372a,0d5b61f7f515a3b7a9d5566b6f4a7be5,40d759b6737d3f4373a42da5e1f369b1,023a557674bb7bbe0ac61751c230e888,fc9425f84a73805fb2165399a8f13f37,f4fca8982b454963149b5b9ac0643621,47f3b06a7090750cbdac6e812aecd590"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-09-03"
        description = "Equation Group hack tool set LSADUMP_Lp_ModifyPrivilege_Lp_PacketScan_Lp_put_Lp_RemoteExecute_Lp_Windows_Lp_wmi_Lp_9 "
	strings:
		$x1 = "Injection Lib -  " wide
		$x2 = "LSADUMP - - ERROR" wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 300KB and 1 of them )
}