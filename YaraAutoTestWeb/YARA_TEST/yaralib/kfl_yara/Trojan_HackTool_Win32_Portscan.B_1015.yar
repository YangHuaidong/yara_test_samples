rule Trojan_HackTool_Linux_Portscan_B_1015
{
	meta:
	    judge = "black"
	    threatname = "Trojan[HackTool]/Linux.Portscan.B"
	    threattype = "HackTool"
	    family = "Portscan"
	    hacker = "None"
	    refer = "51523521acb5cd6f404346c69851740d"
	    comment = "None"
		description = "Linux hack tools - file pscan2"
		author = "Florian Roth -lz"
		reference = "not set"
		date = "2015/01/19"

	strings:
		$s0 = "# pscan completed in %u seconds. (found %d ips)" fullword ascii
		$s1 = "Usage: %s <b-block> <port> [c-block]" fullword ascii
		$s3 = "%s.%d.* (total: %d) (%.1f%% done)" fullword ascii
		$s8 = "Invalid IP." fullword ascii
		$s9 = "# scanning: " fullword ascii
		$s10 = "Unable to allocate socket." fullword ascii
	condition:
		2 of them
}