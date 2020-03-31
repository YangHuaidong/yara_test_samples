rule Virus_Win32_Sality_gen_20171221112019_1003 
{
	meta:
		judge = "black"
		threatname = "Virus/Win32.Sality.gen"
		threattype = "virus"
		family = "Sality"
		hacker = "None"
		refer = "1489c651681188764476d04f7944122a"
		description = "None"
		comment = "None"
		author = "xc"
		date = "2017-10-17"
	strings:
		$s0 = "johnS203@yahoo.com"
		$s1 = "gmail-smtp-in.l.google.com"
		$s2 = "whiat1001@gmail.com"
		$s3 = "et share c$ /d"
		$s4 = "net share admin$ /d"
		$s5 = "lsasvc.exe"
		$s6 = "wglmgr"
		$s7 = "32.dll"

	condition:
		6 of them
}
