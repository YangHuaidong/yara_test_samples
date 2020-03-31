rule Trojan_Backdoor_Win32_EquationDrug_geng_38_73 
{

    meta:
        judge = "black"
				threatname = "Trojan[Backdoor]/Win32.EquationDrug.geng"
				threattype = "Backdoor"
				family = "EquationDrug"
				hacker = "None"
				comment = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/ EquationDrug_NetworkSniffer3"
				date = "2015-03-11"
				author = "Florian Roth @4nc4p--DC"
				description = "EquationDrug - Collector plugin for Volrec - msrstd.sys" 
				refer = "15d39578460e878dd89e8911180494ff"

    strings:
        $s0 = "msrstd.sys" fullword wide
        $s1 = "msrstd.pdb" fullword ascii
        $s2 = "msrstd driver" fullword wide

    condition:
        all of them
}
