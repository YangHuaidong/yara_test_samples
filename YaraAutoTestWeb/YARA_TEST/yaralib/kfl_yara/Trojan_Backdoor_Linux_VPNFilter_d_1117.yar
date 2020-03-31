rule Trojan_Backdoor_Linux_VPNFilter_d_1117
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Linux.VPNFilter.d"
		threattype = "ICS,Backdoor"
		family = "VPNFilter"
		hacker = "None"
		refer = "b5dc976043db9b42c9f6fa889205c68a"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-05-10"
		description = "Detects VPNFilter malware"
    strings:
        $x1 = "We needed to load a secret key from %s, but it was encrypted. Try 'tor --keygen' instead, so you can enter the passphrase." fullword ascii
        $x2 = "Received a VERSION cell with odd payload length %d; closing connection." fullword ascii
        $x3 = "Please upgrade! This version of Tor (%s) is %s, according to the directory authorities. Recommended versions are: %s" fullword ascii
    condition:
        uint16(0) == 0x457f and 1 of them
}