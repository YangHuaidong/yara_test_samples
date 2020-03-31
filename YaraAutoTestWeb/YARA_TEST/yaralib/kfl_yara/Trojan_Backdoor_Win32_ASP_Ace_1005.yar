rule Trojan_Backdoor_Win32_ASP_Ace_1005
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.ASP.Ace"
		threattype = "Backdoor"
		family = "ASP"
		hacker = "None"
		refer = "914e97f0cd5c6d23ba79e9b118553944"
		comment = "None"
		description = "Disclosed hacktool set (old stuff) - file aspfile2.asp"
		author = "Florian Roth"
		date = "23.11.14"
		
	strings:
		$s0 = "response.write \"command completed success!\" " fullword ascii
		$s1 = "for each co in foditems " fullword ascii
		$s3 = "<input type=text name=text6 value=\"<%= szCMD6 %>\"><br> " fullword ascii
		$s19 = "<title>Hello! Welcome </title>" fullword ascii
	condition:
		all of them
}