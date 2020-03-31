rule Trojan_Backdoor_Win32_EquationDrug_genf_37_72 
{

    meta:
        judge = "black"
				threatname = "Trojan[Backdoor]/Win32.EquationDrug.genf"
				threattype = "Backdoor"
				family = "EquationDrug"
				hacker = "None"
				comment = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/ EquationDrug_NetworkSniffer3"
				date = "2015-03-11"
				author = "Florian Roth @4nc4p--DC"
				description = "EquationDrug - Network Sniffer - tdip.sys" 
				refer = "60dab5bb319281747c5863b44c5ac60d"

    strings:
        $s0 = "Corporation. All rights reserved." fullword wide
        $s1 = "IP Transport Driver" fullword wide
        $s2 = "tdip.sys" fullword wide
        $s3 = "tdip.pdb" fullword ascii

    condition:
        all of them
}