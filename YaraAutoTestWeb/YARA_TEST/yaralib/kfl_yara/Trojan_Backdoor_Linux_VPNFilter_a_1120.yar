rule Trojan_Backdoor_Linux_VPNFilter_a_1120
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Linux.VPNFilter.a"
		threattype = "ICS,Backdoor"
		family = "VPNFilter"
		hacker = "None"
		refer = "97444b5209278ed611e6a94076e814c8"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-05-10"
		description = "Detects VPNFilter malware"
    strings:
        $s1 = "Login=" fullword ascii
        $s2 = "Password=" fullword ascii
        $s3 = "%s/rep_%u.bin" fullword ascii
        $s4 = "%s:%uh->%s:%hu" fullword ascii
        $s5 = "Password required" fullword ascii /* Goodware String - occured 1 times */
        $s6 = "password=" fullword ascii /* Goodware String - occured 2 times */
        $s7 = "Authorization: Basic" fullword ascii /* Goodware String - occured 2 times */
        $s8 = "/tmUnblock.cgi" fullword ascii
    condition:
        uint16(0) == 0x457f and filesize < 100KB and all of them
}