rule Trojan_Win32_Bladabindi_b_20161213095255_1107_648 
{
	meta:
		judge = "black"
		threatname = "Trojan/Win32.Bladabindi.b"
		threattype = "rat"
		family = "Bladabindi"
		hacker = "None"
		refer = "2e58e844af9e69f967dae886da72d135"
		description = "SpyGate"
		comment = "None"
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "2016-06-23"
	strings:
		$s0 = "abccba"
		$s1 = "abccbaSpyGateRATabccba" //$a = Version 0.2.6
		$s2 = "StubX.pdb"
		$s3 = "abccbaDanabccb"
		$s4 = "monikerString" nocase //$b = Version 2.0
		$s5 = "virustotal1"
		$s6 = "get_CurrentDomain"
		$s7 = "shutdowncomputer" wide //$c = Version 2.9
		$s8 = "shutdown -r -t 00" wide
		$s9 = "set cdaudio door closed" wide
		$s10 = "FileManagerSplit" wide
		$s11 = "Chating With >> [~Hacker~]" wide

	condition:
		($s1 and $s2 and $s3 and #s0 > 40) or ($s4 and $s5 and $s6 and #s0 > 10) or ($s7 and $s8 and $s9 and $s10 and $s11)
}
