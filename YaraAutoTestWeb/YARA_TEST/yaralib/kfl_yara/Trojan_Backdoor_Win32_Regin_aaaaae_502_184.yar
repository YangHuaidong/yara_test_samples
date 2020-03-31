rule Trojan_Backdoor_Win32_Regin_aaaaae_502_184
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Regin.aaaaae"
        threattype = "Backdoor"
        family = "Regin"
        hacker = "None"
        author = "balala"
        refer = "2c8b9d2885543d7ade3cae98225e263b,4b6b86c7fec1c574706cecedf44abded"
		comment = "None"
        date = "2018-08-02"
        description = "Generic rule for Regin APT kernel driver Malware - Symantec http://t.co/qu53359Cb2"
    

    strings:
        $m0 = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 }    
        $s0 = "KeGetCurrentIrql" fullword ascii
        $s1 = "5.2.3790.0 (srv03_rtm.030324-2048)" fullword wide
        $s2 = "usbclass" fullword wide
        $x1 = "PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" ascii
        $x2 = "Universal Serial Bus Class Driver" fullword wide
        $x3 = "5.2.3790.0" fullword wide
        $y1 = "LSA Shell" fullword wide
        $y2 = "0Richw" fullword ascii       
    
    condition:
        $m0 at 0 and all of ($s*) and ( all of ($x*) or all of ($y*) )  and filesize < 20KB
}