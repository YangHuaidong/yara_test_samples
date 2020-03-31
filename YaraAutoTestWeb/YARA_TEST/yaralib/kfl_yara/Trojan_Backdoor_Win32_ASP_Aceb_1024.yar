rule Trojan_Backdoor_Win32_ASP_Aceb_1024 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.ASP.Aceb"
		threattype = "Backdoor"
		family = "ASP"
		hacker = "None"
		refer = "37519eadc4441b961bda12529d8f4109"
		comment = "None"
		description = "Disclosed hacktool set (old stuff) - file EDIR.ASP"
		author = "Florian Roth"
		date = "23.11.14"
		
	strings:
		$s1 = "response.write \"<a href='index.asp'>" fullword ascii
		$s3 = "if Request.Cookies(\"password\")=\"" ascii
		$s6 = "whichdir=server.mappath(Request(\"path\"))" fullword ascii
		$s7 = "Set fs = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
		$s19 = "whichdir=Request(\"path\")" fullword ascii
	condition:
		all of them
}