rule Trojan_Backdoor_Win32_BearDoor_bbs_54_42 
{
    meta:
        judge = "black"
		threatname = "Trojan[Backdoor]/Win32.BearDoor.bbs"
		threattype = "Backdoor"
		family = "BearDoor"
		hacker = "None"
		comment = "http://feedproxy.google.com/~r/eset/blog/~3/BXJbnGSvEFc/"
		date = "2016-01-03"
		author = "Florian Roth--DC"
		description = "Detects the password of the backdoored DropBear SSH Server - BlackEnergy BlackEnergy_BackdoorPass_DropBear_SSH" 
		refer = "fffeaba10fd83c59c28f025c99d063f8"
    
    strings:
        $s1 = "passDs5Bu9Te7" fullword ascii
    
    condition:
        uint16(0) == 0x5a4d and $s1
}