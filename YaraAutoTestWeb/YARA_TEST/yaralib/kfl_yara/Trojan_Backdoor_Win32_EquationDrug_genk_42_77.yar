rule Trojan_Backdoor_Win32_EquationDrug_genk_42_77 
{

    meta:
        judge = "black"
				threatname = "Trojan[Backdoor]/Win32.EquationDrug.genk"
				threattype = "Backdoor"
				family = "EquationDrug"
				hacker = "None"
				comment = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/ EquationDrug_PlatformOrchestrator"
				date = "2015-03-11"
				author = "Florian Roth @4nc4p--DC"
				description = "EquationDrug - Platform orchestrator - mscfg32.dll, svchost32.dll" 
				refer = "5767b9d851d0c24e13eca1bfd16ea424"


    strings:
        $s0 = "SERVICES.EXE" fullword wide
        $s1 = "\\command.com" fullword wide
        $s2 = "Microsoft(R) Windows (TM) Operating System" fullword wide
        $s3 = "LSASS.EXE" fullword wide
        $s4 = "Windows Configuration Services" fullword wide
        $s8 = "unilay.dll" fullword ascii

    condition:
        all of them
}
