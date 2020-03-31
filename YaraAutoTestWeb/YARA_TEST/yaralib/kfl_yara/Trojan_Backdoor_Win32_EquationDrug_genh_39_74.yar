rule Trojan_Backdoor_Win32_EquationDrug_genh_39_74 
{

    meta:
        judge = "black"
				threatname = "Trojan[Backdoor]/Win32.EquationDrug.genh"
				threattype = "Backdoor"
				family = "EquationDrug"
				hacker = "None"
				comment = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/ EquationDrug_KernelRootkit"
				date = "2015-03-11"
				author = "Florian Roth @4nc4p--DC"
				description = "EquationDrug - Kernel mode stage 0 and rootkit (Windows 2000 and above) - msndsrv.sys" 
				refer = "c4f8671c1f00dab30f5f88d684af1927"

    strings:
        $s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
        $s1 = "Parmsndsrv.dbg" fullword ascii
        $s2 = "\\Registry\\User\\CurrentUser\\" fullword wide
        $s3 = "msndsrv.sys" fullword wide
        $s5 = "\\REGISTRY\\MACHINE\\System\\CurrentControlSet\\Control\\Windows" fullword wide
        $s6 = "\\Device\\%ws_%ws" fullword wide
        $s7 = "\\DosDevices\\%ws" fullword wide
        $s9 = "\\Device\\%ws" fullword wide

    condition:
        all of them
}
