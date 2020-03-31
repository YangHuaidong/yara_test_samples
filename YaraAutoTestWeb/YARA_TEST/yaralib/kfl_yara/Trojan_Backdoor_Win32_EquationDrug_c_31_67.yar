rule Trojan_Backdoor_Win32_EquationDrug_c_31_67 
{

    meta:
        
        judge = "black"
				threatname = "Trojan[Backdoor]/Win32.EquationDrug.c"
				threattype = "Backdoor"
				family = "EquationDrug"
				hacker = "None"
				comment = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/ EquationDrug_HDDSSD_Op"
				date = "2015-03-11"
				author = "Florian Roth @4nc4p--DC"
				description = "EquationDrug - HDD/SSD firmware operation - nls_933w.dll" 
				refer = "11fb08b9126cdb4668b3f5135cf7a6c5"

    strings:
        $s0 = "nls_933w.dll" fullword ascii

    condition:
        all of them
}
