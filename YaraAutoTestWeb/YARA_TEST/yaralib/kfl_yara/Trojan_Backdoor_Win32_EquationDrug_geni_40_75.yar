rule Trojan_Backdoor_Win32_EquationDrug_geni_40_75 
{

    meta:
        judge = "black"
				threatname = "Trojan[Backdoor]/Win32.EquationDrug.geni"
				threattype = "Backdoor"
				family = "EquationDrug"
				hacker = "None"
				comment = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/ EquationDrug_Keylogger"
				date = "2015-03-11"
				author = "Florian Roth @4nc4p--DC"
				description = "EquationDrug - Key/clipboard logger driver - msrtvd.sys" 
				refer = "f6bf3ed3bcd466e5fd1cbaf6ba658716"

    strings:
        $s0 = "\\registry\\machine\\software\\Microsoft\\Windows NT\\CurrentVersion" fullword wide
        $s2 = "\\registry\\machine\\SYSTEM\\ControlSet001\\Control\\Session Manager\\En" wide
        $s3 = "\\DosDevices\\Gk" fullword wide
        $s5 = "\\Device\\Gk0" fullword wide

    condition:
        all of them
}