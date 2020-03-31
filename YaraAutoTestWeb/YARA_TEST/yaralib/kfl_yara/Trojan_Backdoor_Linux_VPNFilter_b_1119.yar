rule Trojan_Backdoor_Linux_VPNFilter_b_1119
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Linux.VPNFilter.b"
		threattype = "ICS,Backdoor"
		family = "VPNFilter"
		hacker = "None"
		refer = "45871bad3a9b4594fc3de39e4b5930ad"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-05-10"
		description = "Detects VPNFilter malware"
    strings:
        $s1 = "User-Agent: Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.2; Trident/4.0)" fullword ascii
        $s2 = "passwordPASSWORDpassword" fullword ascii
        $s3 = "/tmp/client.key" fullword ascii
    condition:
        uint16(0) == 0x457f and filesize < 1000KB and all of them
}