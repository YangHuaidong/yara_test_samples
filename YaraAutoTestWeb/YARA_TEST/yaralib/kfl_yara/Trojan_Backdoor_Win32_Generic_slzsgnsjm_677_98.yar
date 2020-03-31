rule Trojan_Backdoor_Win32_Generic_slzsgnsjm_677_98
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Generic.slzsgnsjm"
        threattype = "Backdoor"
        family = "Generic"
        hacker = "None"
        author = "balala"
        refer = "7b18614df95e71032909beb25a7b1e87"
        comment = "None"
        date = "2018-09-05"
        description = "None"
	strings:
        $s1 = "adbrowser" fullword wide 
        $s2 = "IJKLlGdmaWhram0vn36BgIOChYR3L45xcHNydXQvhmloa2ptbH8voYCDTw==" fullword ascii
        $s3 = "EFGHlGdmaWhrL41sf36BgIOCL6R3dk8=" fullword ascii
    
    condition:
        uint16(0) == 0x5a4d and filesize < 300KB and all of them

}