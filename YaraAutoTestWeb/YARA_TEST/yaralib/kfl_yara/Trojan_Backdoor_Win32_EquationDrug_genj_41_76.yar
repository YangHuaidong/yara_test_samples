rule Trojan_Backdoor_Win32_EquationDrug_genj_41_76 
{

    meta:
       
        judge = "black"
				threatname = "Trojan[Backdoor]/Win32.EquationDrug.genj"
				threattype = "Backdoor"
				family = "EquationDrug"
				hacker = "None"
				comment = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/ EquationDrug_NetworkSniffer4"
				date = "2015-03-11"
				author = "Florian Roth @4nc4p--DC"
				description = "EquationDrug - Network-sniffer/patcher - atmdkdrv.sys" 
				refer = "214f7a2c95bdc265888fbcd24e3587da"

    strings:
        $s0 = "Copyright 1999 RAVISENT Technologies Inc." fullword wide
        $s1 = "\\systemroot\\" fullword ascii
        $s2 = "RAVISENT Technologies Inc." fullword wide
        $s3 = "Created by VIONA Development" fullword wide
        $s4 = "\\Registry\\User\\CurrentUser\\" fullword wide
        $s5 = "\\device\\harddiskvolume" fullword wide
        $s7 = "ATMDKDRV.SYS" fullword wide
        $s8 = "\\Device\\%ws_%ws" fullword wide
        $s9 = "\\DosDevices\\%ws" fullword wide
        $s10 = "CineMaster C 1.1 WDM Main Driver" fullword wide
        $s11 = "\\Device\\%ws" fullword wide
        $s13 = "CineMaster C 1.1 WDM" fullword wide

    condition:
        all of them
}