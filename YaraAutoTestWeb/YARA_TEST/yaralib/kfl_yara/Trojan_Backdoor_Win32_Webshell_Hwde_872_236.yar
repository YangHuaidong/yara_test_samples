rule Trojan_Backdoor_Win32_Webshell_Hwde_872_236
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Webshell.Hwde"
        threattype = "Backdoor"
        family = "Webshell"
        hacker = "None"
        author = "copy"
        refer = "2cf20a207695bbc2311a998d1d795c35"
        comment = "None"
        date = "2018-11-13"
        description = "Web Shell - file sql.php"
	strings:
		$s0 = "$result=mysql_list_tables($db) or die (\"$h_error<b>\".mysql_error().\"</b>$f_"
		$s4 = "print \"<a href=\\\"$_SERVER[PHP_SELF]?s=$s&login=$login&passwd=$passwd&"
	condition:
		all of them
}