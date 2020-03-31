rule Trojan_Backdoor_Win32_Sofacy_xwyqj_682_214
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Sofacy.xwyqj"
        threattype = "backdoor"
        family = "Sofacy"
        hacker = "None"
        author = "balala"
        refer = "a34734b3904ef24909ecc8a6d7a5aece,c2988e3e4f70d5901b234ff1c1363dcc,45fb46519b97acae722192304c804894"
        comment = "None"
        date = "2018-08-30"
        description = "None"
	strings:
        $x1 = "DGMNOEP" fullword ascii
        $x2 = "/%s%s%s/?%s=" fullword ascii
        $s1 = "Control Panel\\Dehttps=https://%snetwork.proxy.ht2" fullword ascii
        $s2 = "http=http://%s:%Control Panel\\Denetwork.proxy.ht&ol1mS9" fullword ascii
        $s3 = "svchost.dll" fullword wide
        $s4 = "clconfig.dll" fullword wide
    
    condition:
        ( uint16(0) == 0x5a4d and filesize < 100KB and ( all of ($x*) ) ) or ( 3 of them )
}