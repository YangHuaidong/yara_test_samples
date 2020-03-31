rule Trojan_Backdoor_Linux_Slice_a_674
{
    meta:
	    judge = "black"
		threatname = "Trojan[Backdoor]/Linux.Slice.a"
		threattype = "Backdoor"
		family = "Slice"
		hacker = "None"
		refer = "a8b03eff9ba7e9b3d5176b1204c20a08"
		author = "mqx"
		comment = "None"
		date = "2017-10-16"
		description = "None"
	strings:
	    $s0 = "%i.%i.%i.%i"
		$s1 = "socket"
		$s2 = "sendto"
		$s3 = "Usage: %s srcaddr dstaddr low high\n"
	condition:
	    all of them		
}