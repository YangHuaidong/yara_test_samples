rule Trojan_Backdoor_Win32_BlackEnergy2_BearDoor_1069
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.BlackEnergy2.BearDoor"
		threattype = "ICS,Backdoor"
		family = "BlackEnergy2"
		hacker = "None"
		refer = "fffeaba10fd83c59c28f025c99d063f8"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-03-09"
		description = "None"
    strings:
        $s1 = "Dropbear server v%s https://matt.ucc.asn.au/dropbear/dropbear.html" fullword ascii
        $s2 = "Badly formatted command= authorized_keys option" fullword ascii
        $s3 = "This Dropbear program does not support '%s' %s algorithm" fullword ascii
        $s4 = "/etc/dropbear/dropbear_dss_host_key" fullword ascii
        $s5 = "/etc/dropbear/dropbear_rsa_host_key" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 1000KB and 2 of them
}