rule Trojan_Backdoor_Win32_EquationDrug_k_45_81
{

    meta:
        judge = "black"
				threatname = "Trojan[Backdoor]/Win32.EquationDrug.k"
				threattype = "Backdoor"
				family = "EquationDrug"
				hacker = "None"
				comment = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/ EquationDrug_NetworkSniffer1"
				date = "2015-03-11"
				author = "Florian Roth @4nc4p--DC"
				description = "EquationDrug - Backdoor driven by network sniffer - mstcp32.sys, fat32.sys" 
				refer = "74de13b5ea68b3da24addc009f84baee"

    strings:
        $s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
        $s1 = "\\Registry\\User\\CurrentUser\\" fullword wide
        $s3 = "sys\\mstcp32.dbg" fullword ascii
        $s7 = "mstcp32.sys" fullword wide
        $s8 = "p32.sys" fullword ascii
        $s9 = "\\Device\\%ws_%ws" fullword wide
        $s10 = "\\DosDevices\\%ws" fullword wide
        $s11 = "\\Device\\%ws" fullword wide
    
    condition:
        all of them
}