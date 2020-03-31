rule Trojan_RAT_Win32_Havex_b_1155
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Havex.b"
		threattype = "ICS,RAT"
		family = "Havex"
		hacker = "None"
		refer = "03b9436ae41dc3d30bce7217ee2cd25a"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-04-22"
		description = "Detects the Havex RAT malware"
	strings:
		$s0 = "ipts.exe"
	    $s1 = "iptstask.exe"
		$s2 = "vmware"
		$s3 = {5C 25 73 2D 25 64 2D 25 30 38 78 2D 25 30 38 78 2D 25 64 2D 25 64 2E 64 6D 70 2E 67 7A} //\%s-%d-%08x-%08x-%d-%d.dmp.gz
		$s4 = ".mixcrt"
		$s5 = "ipts.pdb"
	condition:
	    all of them
}