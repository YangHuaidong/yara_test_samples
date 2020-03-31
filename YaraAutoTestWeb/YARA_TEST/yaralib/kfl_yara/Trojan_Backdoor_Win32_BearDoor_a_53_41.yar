rule Trojan_Backdoor_Win32_BearDoor_a_53_41
 {

    meta:
        judge = "black"
		threatname = "Trojan[Backdoor]/Win32.BearDoor.a"
		threattype = "Backdoor"
		family = "BearDoor"
		hacker = "None"
		comment = "http://feedproxy.google.com/~r/eset/blog/~3/BXJbnGSvEFc/"
		date = "2015-05-14"
		author = "Florian Roth--DC"
		description = "Detects DropBear SSH Server (not a threat but used to maintain access)" 
		refer = "4c21336dad66ebed2f7ee45d41e6cada"
        score = 50
        
    strings:
        $s1 = "Dropbear server v%s https://matt.ucc.asn.au/dropbear/dropbear.html" fullword ascii
        $s2 = "Badly formatted command= authorized_keys option" fullword ascii
        $s3 = "This Dropbear program does not support '%s' %s algorithm" fullword ascii
        $s4 = "/etc/dropbear/dropbear_dss_host_key" fullword ascii
        $s5 = "/etc/dropbear/dropbear_rsa_host_key" fullword ascii
    
    condition:
        uint16(0) == 0x5a4d and filesize < 1000KB and 2 of them
}