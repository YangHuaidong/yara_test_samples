rule Trojan_Backdoor_Win32_EquationDrug_genl_43_78 
{

    meta:
        judge = "black"
				threatname = "Trojan[Backdoor]/Win32.EquationDrug.genl"
				threattype = "Backdoor"
				family = "EquationDrug"
				hacker = "None"
				comment = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/ EquationDrug_NetworkSniffer5"
				date = "2015-03-11"
				author = "Florian Roth @4nc4p--DC"
				description = "EquationDrug - Network-sniffer/patcher - atmdkdrv.sys" 
				refer = "8d87a1845122bf090b3d8656dc9d60a8"


    strings:
        $s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
        $s1 = "\\Registry\\User\\CurrentUser\\" fullword wide
        $s2 = "atmdkdrv.sys" fullword wide
        $s4 = "\\Device\\%ws_%ws" fullword wide
        $s5 = "\\DosDevices\\%ws" fullword wide
        $s6 = "\\Device\\%ws" fullword wide

    condition:
        all of them
}