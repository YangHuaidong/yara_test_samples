rule Trojan_Backdoor_Linux_Gafgyt_npx_20170822160859_841 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Linux.Gafgyt.npx"
		threattype = "BackDoor"
		family = "Gafgyt"
		hacker = "None"
		refer = "7e1c3834c38984c34b6fd4c741ae3a21"
		description = "None"
		comment = "None"
		author = "xc"
		date = "2017-08-17"
	strings:
		$x1 = "ftpupload.sh" fullword ascii
		$x2 = "/dev/misc/watchdog" fullword ascii
		$x3 = "/dev/watchdog" ascii
		$x4 = ":52869/picsdesc.xml" fullword ascii
		$x5 = "npxXoudifFeEgGaACScs" fullword ascii
		$s1 = "ftptest.cgi" fullword ascii
		$s2 = "set_ftp.cgi" fullword ascii
		$s3 = "2580e538f3723927f1ea2fdb8d57b99e9cc37ced1" fullword ascii
		$s4 = "023ea8c671c0abf77241886465200cf81b1a2bf5e" fullword ascii

	condition:
		uint16(0) == 0x457f and filesize < 300KB and ( ( 1 of ($x*) and 1 of ($s*) ) or 2 of ($s*) )
}
