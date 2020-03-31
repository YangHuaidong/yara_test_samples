rule Trojan_Backdoor_Win32_EquationDrug_genb_34_69 
{
    meta:
        judge = "black"
				threatname = "Trojan[Backdoor]/Win32.EquationDrug.genb"
				threattype = "Backdoor"
				family = "EquationDrug"
				hacker = "None"
				comment = "http://goo.gl/ivt8EW Equation_Kaspersky_EOP_Package"
				date = "2015-02-16"
				author = "Florian Roth--DC"
				description = "Equation Group Malware - EoP package and malware launcher" 
				refer = "6fe6c03b938580ebf9b82f3b9cd4c4aa"
        
        
    strings:
        $mz = { 4d 5a }
        $s0 = "abababababab" fullword ascii
        $s1 = "abcdefghijklmnopq" fullword ascii
        $s2 = "@STATIC" fullword wide
        $s3 = "$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" fullword ascii
        $s4 = "@prkMtx" fullword wide
        $s5 = "prkMtx" fullword wide
        $s6 = "cnFormVoidFBC" fullword wide

    condition:
        ( $mz at 0 ) and filesize < 100000 and all of ($s*)
}