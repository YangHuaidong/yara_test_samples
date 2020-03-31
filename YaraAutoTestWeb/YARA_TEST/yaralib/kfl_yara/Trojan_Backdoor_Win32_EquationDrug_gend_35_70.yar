rule Trojan_Backdoor_Win32_EquationDrug_gend_35_70 
{

    meta:
        judge = "black"
				threatname = "Trojan[Backdoor]/Win32.EquationDrug.gend"
				threattype = "Backdoor"
				family = "EquationDrug"
				hacker = "None"
				comment = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/ EquationDrug_CompatLayer_UnilayDLL"
				date = "2015-03-11"
				author = "Florian Roth @4nc4p--DC"
				description = "EquationDrug - Unilay.DLL" 
				refer = "ef4405930e6071ae1f7f6fa7d4f3397d"
        

    strings:
        $mz = { 4d 5a }
        $s0 = "unilay.dll" fullword ascii

    condition:
        ( $mz at 0 ) and $s0
}