rule Trojan_Backdoor_Win32_TripleFantasy_genc_49_228 
{

    meta:
        judge = "black"
				threatname = "Trojan[Backdoor]/Win32.TripleFantasy.genc"
				threattype = "Backdoor"
				family = "TripleFantasy"
				hacker = "None"
				comment = "http://goo.gl/ivt8EW Equation_Kaspersky_TripleFantasy_Loader"
				date = "2015-02-16"
				author = "Florian Roth--DC"
				description = "Equation Group Malware - TripleFantasy Loader" 
				refer = "9180d5affe1e5df0717d7385e7f54386"
    
    strings:
        $mz = { 4d 5a }
        $x1 = "Original Innovations, LLC" fullword wide
        $x2 = "Moniter Resource Protocol" fullword wide
        $x3 = "ahlhcib.dll" fullword wide
        $s0 = "hnetcfg.HNetGetSharingServicesPage" fullword ascii
        $s1 = "hnetcfg.IcfGetOperationalMode" fullword ascii
        $s2 = "hnetcfg.IcfGetDynamicFwPorts" fullword ascii
        $s3 = "hnetcfg.HNetFreeFirewallLoggingSettings" fullword ascii
        $s4 = "hnetcfg.HNetGetShareAndBridgeSettings" fullword ascii
        $s5 = "hnetcfg.HNetGetFirewallSettingsPage" fullword ascii
    
    condition:
        ( $mz at 0 ) and filesize < 50000 and ( all of ($x*) and all of ($s*) )
}
