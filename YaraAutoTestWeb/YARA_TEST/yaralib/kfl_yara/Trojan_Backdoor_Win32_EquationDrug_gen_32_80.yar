rule Trojan_Backdoor_Win32_EquationDrug_gen_32_80
{

    meta:
        
        judge = "black"
				threatname = "Trojan[Backdoor]/Win32.EquationDrug.gen"
				threattype = "Backdoor"
				family = "EquationDrug"
				hacker = "None"
				comment = "http://goo.gl/ivt8EW Equation_Kaspersky_GROK_Keylogger"
				date = "2015-02-16"
				author = "Florian Roth--DC"
				description = "Equation Group Malware - GROK keylogger http://goo.gl/ivt8EW" 
				refer = "24a6ec8ebf9c0867ed1c097f4a653b8d"

    strings:
        $mz = { 4d 5a }
        $s0 = "c:\\users\\rmgree5\\" ascii
        $s1 = "msrtdv.sys" fullword wide
        $x1 = "svrg.pdb" fullword ascii
        $x2 = "W32pServiceTable" fullword ascii
        $x3 = "In forma" fullword ascii
        $x4 = "ReleaseF" fullword ascii
        $x5 = "criptor" fullword ascii
        $x6 = "astMutex" fullword ascii
        $x7 = "ARASATAU" fullword ascii
        $x8 = "R0omp4ar" fullword ascii
        $z1 = "H.text" fullword ascii
        $z2 = "\\registry\\machine\\software\\Microsoft\\Windows NT\\CurrentVersion" fullword wide
        $z4 = "\\registry\\machine\\SYSTEM\\ControlSet001\\Control\\Session Manager\\Environment" wide fullword

    condition:
        ( $mz at 0 ) and filesize < 250000 and ($s0 or ( $s1 and 6 of ($x*) ) or ( 6 of ($x*) and all of ($z*) ))
}
