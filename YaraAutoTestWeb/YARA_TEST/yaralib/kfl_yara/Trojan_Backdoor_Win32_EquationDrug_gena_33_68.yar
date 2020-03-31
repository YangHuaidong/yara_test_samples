rule Trojan_Backdoor_Win32_EquationDrug_gena_33_68
{
    meta:
        judge = "black"
				threatname = "Trojan[Backdoor]/Win32.EquationDrug.gena"
				threattype = "Backdoor"
				family = "EquationDrug"
				hacker = "None"
				comment = "http://goo.gl/ivt8EW Equation_Kaspersky_EquationDrugInstaller"
				date = "2015-02-16"
				author = "Florian Roth--DC"
				description = "Equation Group Malware - EquationDrug installer LUTEUSOBSTOS" 
				refer = "4556ce5eb007af1de5bd3b457f0b216d"

    strings:
        $mz = { 4d 5a }

        $s0 = "\\system32\\win32k.sys" fullword wide
        $s1 = "ALL_FIREWALLS" fullword ascii
        $x1 = "@prkMtx" fullword wide
        $x2 = "STATIC" fullword wide
        $x3 = "windir" fullword wide
        $x4 = "cnFormVoidFBC" fullword wide
        $x5 = "CcnFormSyncExFBC" fullword wide
        $x6 = "WinStaObj" fullword wide
        $x7 = "BINRES" fullword wide

    condition:
        ( $mz at 0 ) and filesize < 500000 and all of ($s*) and 5 of ($x*)
}