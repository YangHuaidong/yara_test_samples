rule Trojan_Backdoor_Win32_EquationDrug_genm_44_79 
{

    meta:        
        judge = "black"
				threatname = "Trojan[Backdoor]/Win32.EquationDrug.genm"
				threattype = "Backdoor"
				family = "EquationDrug"
				hacker = "None"
				comment = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/ EquationDrug_FileSystem_Filter"
				date = "2015-03-11"
				author = "Florian Roth @4nc4p--DC"
				description = "EquationDrug - Filesystem filter driver – volrec.sys, scsi2mgr.sys" 
				refer = "c17e16a54916d3838f63d208ebab9879"

    strings:
        $s0 = "volrec.sys" fullword wide
        $s1 = "volrec.pdb" fullword ascii
        $s2 = "Volume recognizer driver" fullword wide

    condition:
        all of them
}