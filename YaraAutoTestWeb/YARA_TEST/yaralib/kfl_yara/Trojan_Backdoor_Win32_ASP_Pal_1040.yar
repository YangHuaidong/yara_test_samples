rule Trojan_Backdoor_Win32_ASP_Pal_1040
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.ASP.Pal"
        threattype = "Backdoor"
        family = "ASP"
        hacker = "None"
        author = "copy"
        refer = "e63f5a96570e1faf4c7b8ca6df750237"
        comment = "None"
        date = "2018-12-13"
        description = "Web Shell - file shell.asp"
		score = 70
	strings:
		$s7 = "<input type=\"submit\" name=\"Send\" value=\"GO!\">" fullword
		$s8 = "<TEXTAREA NAME=\"1988\" ROWS=\"18\" COLS=\"78\"></TEXTAREA>" fullword
	condition:
		all of them
}