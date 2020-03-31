rule Virus_Win32_Nimnul_wzq_20170705104805_1122_665 
{
	meta:
		judge = "black"
		threatname = "Virus/Win32.Nimnul.wzq"
		threattype = "virus"
		family = "Nimnul"
		hacker = "none"
		refer = "c62393a4aafbd4bfac5d4f3cf1c2eb94"
		description = "None"
		comment = "none"
		author = "xc"
		date = "2017-06-27"
	strings:
		$s0 = "Srv.exe"
		$s1 = "*.wzq"

	condition:
		all of them
}
