rule Trojan_HACKTOOL_Win32_QuarksPwDump_Gen_777_541
{
	meta:
		judge = "black"
	    threatname = "Trojan[HACKTOOL]/Win32.QuarksPwDump.Gen"
	    threattype = "HACKTOOL"
	    family = "QuarksPwDump"
	    hacker = "None"
	    refer = "312ca371fb8f8b09712e18a7ee609969,1cbe7a8a237dc6e7622111738ea7de02,553b1d2e710e53c2a998c4c13348642d,03f2ba50f64d9d14505651fa045249ff,11aa4b116724d3e4bf343da7354e275f,544642ffe59f54b9c5af4b20ec2678b2,b66c0529af3ead379d9ab0ed7c97a274"
	    comment = "None"
		description = "Detects all QuarksPWDump versions -lz"
		author = "Florian Roth"
		date = "2015-09-29"
	
	strings:
		$s1 = "OpenProcessToken() error: 0x%08X" fullword ascii
		$s2 = "%d dumped" fullword ascii
		$s3 = "AdjustTokenPrivileges() error: 0x%08X" fullword ascii
		$s4 = "\\SAM-%u.dmp" fullword ascii
	condition:
		all of them
}
