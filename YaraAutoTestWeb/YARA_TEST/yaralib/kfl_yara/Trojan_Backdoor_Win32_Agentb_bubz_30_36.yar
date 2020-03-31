rule Trojan_Backdoor_Win32_Agentb_bubz_30_36
{
    meta:
        judge = "black"
				threatname = "Trojan[Backdoor]/Win32.Agentb.bubz"
				threattype = "Backdoor"
				family = "Agentb"
				hacker = "None"
				comment = "http://goo.gl/ivt8EW Equation_Kaspersky_GreyFishInstaller"
				date = "2015-02-16"
				author = "Florian Roth--DC"
				description = "Equation Group Malware - Grey Fish http://goo.gl/ivt8EW" 
				refer = "9b1ca66aab784dc5f1dfe635d8f8a904"

    strings:
        $s0 = "DOGROUND.exe" fullword wide
        $s1 = "Windows Configuration Services" fullword wide
        $s2 = "GetMappedFilenameW" fullword ascii

    condition:
        all of them
}
