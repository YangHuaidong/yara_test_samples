rule Trojan_RAT_Win32_Havex_1073
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Havex"
		threattype = "ICS,RAT"
		family = "Havex"
		hacker = "None"
		refer = "ba8da708b8784afd36c44bb5f1f436bc"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-03-09"
		description = "Detects the Havex RAT malware"
	strings:
		$magic = { 4d 5a }	
	    $s1 = "Start finging of LAN hosts..." fullword wide
		$s2 = "Finding was fault. Unexpective error" fullword wide
		$s3 = "Hosts was't found." fullword wide
		$s4 = "%s[%s]!!!EXEPTION %i!!!" fullword wide
		$s5 = "%s  <%s> (Type=%i, Access=%i, ID='%s')" fullword wide
		$s6 = "Was found %i hosts in LAN:" fullword wide
		$x1 = "MB Connect Line GmbH" wide fullword
		$x2 = "mbCHECK" wide fullword
	condition:
	    $magic at 0 and ( 2 of ($s*) or all of ($x*) )
}