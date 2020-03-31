rule Trojan_Backdoor_Win32_Havex_mbCheck_20161213095116_914_105 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Havex.mbCheck"
		threattype = "BackDoor"
		family = "Havex"
		hacker = "None"
		refer = "1d6b11f85debdda27e873662e721289e"
		description = "Detects the Havex RAT malware,http://www.freebuf.com/articles/system/38525.html"
		comment = "None"
		author = "Florian Roth"
		date = "2014-06-24"
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
