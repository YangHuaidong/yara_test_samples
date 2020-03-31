rule Trojan_Backdoor_Win32_EquationDrug_gene_36_71 
{
    meta:      
        judge = "black"
				threatname = "Trojan[Backdoor]/Win32.EquationDrug.gene"
				threattype = "Backdoor"
				family = "EquationDrug"
				hacker = "None"
				comment = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/ EquationDrug_NetworkSniffer2"
				date = "2015-03-11"
				author = "Florian Roth @4nc4p--DC"
				description = "EquationDrug - Network Sniffer - tdip.sys" 
				refer = "20506375665a6a62f7d9dd22d1cc9870"

    strings:
        $s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
        $s1 = "IP Transport Driver" fullword wide
        $s2 = "tdip.sys" fullword wide
        $s3 = "sys\\tdip.dbg" fullword ascii
        $s4 = "dip.sys" fullword ascii
        $s5 = "\\Device\\%ws_%ws" fullword wide
        $s6 = "\\DosDevices\\%ws" fullword wide
        $s7 = "\\Device\\%ws" fullword wide

    condition:
        all of them
}
