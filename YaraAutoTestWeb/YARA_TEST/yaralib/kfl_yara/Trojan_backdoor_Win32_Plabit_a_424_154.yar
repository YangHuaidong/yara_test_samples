rule Trojan_backdoor_Win32_Plabit_a_424_154
{

    meta:
				judge = "black"
				threatname = "Trojan[backdoor]/Win32.Plabit.a"
				threattype = "backdoor"
				family = "Plabit"
				hacker = "None"
				comment = "None"
				date = "2016-04-12"
				author = "Microsoft-DC"
				description = "Installer component" 
				refer = "6d1169775a552230302131f9385135d3"
				sh1 = "6d1169775a552230302131f9385135d385efd166"
    
    strings:
        $str1 = {4b D3 91 49 A1 80 91 42 83 B6 33 28 36 6B 90 97}
        $str2 = "GetInstanceW"
        $str3 = {8B D0 83 E2 1F 8A 14 0A 30 14 30 40 3B 44 24 04 72 EE}
    
    condition:
        $str1 and $str2 and $str3
}