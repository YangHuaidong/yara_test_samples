rule Trojan_DDoS_Win32_Nitol_49_1049
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Nitol.Ex"
		threattype = "DDoS"
		family = "Nitol"
		hacker = "None"
		refer = "41756733fa51a85a5d55f5f9e2852e0a"
		author = "lizhenling"
		comment = "None"
		date = "2019-2-20"
		description = "None"

	strings:		
		$s0 = "caonima"
		$s1 = "%c%c%c%c%ccn.exe"
		$s2 = "woaini"
		$s3 = "C:\\g1fd.exe"
		$s4 = "\\%s\\C$\\NewArean.exe"
		$s5 = "\\Release\\Crazeff.pdb"
		$s6 = "5201314"
		
	condition:
		all of them
}