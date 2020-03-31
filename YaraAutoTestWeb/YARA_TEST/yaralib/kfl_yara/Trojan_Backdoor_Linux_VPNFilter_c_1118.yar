rule Trojan_Backdoor_Linux_VPNFilter_c_1118
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Linux.VPNFilter.c"
		threattype = "ICS,Backdoor"
		family = "VPNFilter"
		hacker = "None"
		refer = "5f358afee76f2a74b1a3443c6012b27b"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-05-10"
		description = "Detects VPNFilter malware"
    strings:
        $sx1 = "User-Agent: Mozilla/6.1 (compatible; MSIE 9.0; Windows NT 5.3; Trident/5.0)" fullword ascii
        $sx2 = "Execute by shell[%d]:" fullword ascii
        $sx3 = "CONFIG.TOR.name:" fullword ascii
        
        $s1 = "Executing command:  %s %s..." fullword ascii
        $s2 = "/proc/%d/cmdline" fullword ascii
        
        $a1 = "Mozilla/5.0 Firefox/50.0" fullword ascii
        $a2 = "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:52.0) Gecko/20100101 Firefox/52.0" fullword ascii
        $a3 = "Mozilla/5.0 (Windows NT 6.1; rv:52.0) Gecko/20100101 Firefox/52.0" fullword ascii
    condition:
        uint16(0) == 0x457f and filesize < 1000KB and ( 1 of ($sx*) or 2 of ($s*) or 2 of ($a*) )
}