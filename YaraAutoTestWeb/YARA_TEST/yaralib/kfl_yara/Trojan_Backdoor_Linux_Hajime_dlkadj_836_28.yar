rule Trojan_Backdoor_Linux_Hajime_dlkadj_836_28
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Linux.Hajime.dlkadj"
		threattype = "Backdoor"
		family = "Hajime"
		hacker = "None"
		author = "ljy"
		refer = "6f39d7311091166a285fb0654b454761"
		comment = "None"
		date = "2018-11-21"
		description = "None"
	strings:
		$userpass = "%d (!=0),user/pass auth will not work, ignored.\n"
		$etcTZ = "/etc/TZ"
		$Mvrs = ",M4.1.0,M10.5.0"
		$bld = "%u.%u.%u.%u.in-addr.arpa"

	condition:
		$userpass and $etcTZ and $Mvrs and $bld 
}
