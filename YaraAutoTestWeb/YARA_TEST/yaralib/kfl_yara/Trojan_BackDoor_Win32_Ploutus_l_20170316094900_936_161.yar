rule Trojan_BackDoor_Win32_Ploutus_l_20170316094900_936_161 
{
	meta:
		judge = "black"
		threatname = "Trojan[BackDoor]/Win32.Ploutus.l"
		threattype = "BackDoor"
		family = "Ploutus"
		hacker = "None"
		refer = "328EC445FCE0EC1E15972FEF9EC4CE38"
		description = "None"
		comment = "None"
		author = "cjf"
		date = "2017-03-02"
	strings:
		$s0 = "Diebold" fullword
		$s1 = "FromBase64String"
		$s2 = "Diebold.exe" fullword
		$s3 = "get_ProcessName"

	condition:
		all of them
}
