rule Trojan_RAT_Win32_DarkComet_4_20161213095220_1081_604 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.DarkComet.4"
		threattype = "rat"
		family = "DarkComet"
		hacker = "None"
		refer = "37b3f4d89a12086a950130fc6a800f41"
		description = "Vertex"
		comment = "None"
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "2016-06-23"
	strings:
		$s0 = "DEFPATH"
		$s1 = "HKNAME"
		$s2 = "HPORT"
		$s3 = "INSTALL"
		$s4 = "IPATH"
		$s5 = "MUTEX"
		$s6 = "PANELPATH"
		$s7 = "ROOTURL"

	condition:
		all of them
}
